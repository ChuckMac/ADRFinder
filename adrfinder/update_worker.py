import threading
import queue
import time
import datetime
from . import get_restaurants_and_times

# A single update worker
#
# Requests for checking on a single site(watch) from a queue of watches
# (another process inserts watches into the queue that are time-ready for checking)


class update_worker(threading.Thread):
    current_uuid = None

    def __init__(self, q, notification_q, app, datastore, *args, **kwargs):
        self.q = q
        self.app = app
        self.notification_q = notification_q
        self.datastore = datastore
        super().__init__(*args, **kwargs)

    def run(self):
        from adrfinder import fetch_site_status

        update_handler = fetch_site_status.perform_site_check(datastore=self.datastore)

        while not self.app.config.exit.is_set():

            try:
                uuid = self.q.get(block=False)
            except queue.Empty:
                pass

            else:
                self.current_uuid = uuid
                from adrfinder import content_fetcher

                if uuid in list(self.datastore.data['watching'].keys()):

                    available_detected = False
                    ## Try to reset any errros
                    data =  {'last_notification_error': False, 'last_error': False}
                    now = time.time()

                    try:
                        available_detected, offers = update_handler.run(uuid)

                    except PermissionError as e:
                        self.app.logger.error("File permission error updating", uuid, str(e))
                    except content_fetcher.EmptyReply as e:
                        # Some kind of custom to-str handler in the exception handler that does this?
                        err_text = "EmptyReply: Status Code {}".format(e.status_code)
                        self.datastore.update_watch(uuid=uuid, data={'last_error': err_text,
                                                                           'last_check_status': e.status_code})
                    except Exception as e:
                        self.app.logger.error("Exception reached processing watch UUID: %s - %s", uuid, str(e))
                        self.datastore.update_watch(uuid=uuid, data={'last_error': str(e)})

                    else:
                        try:
                            watch = self.datastore.data['watching'][uuid]

                            curr_date = int(round(time.time()))

                            if available_detected:
                                data['last_changed'] = curr_date

                            # Generally update anything interesting returned
                            self.datastore.update_watch(uuid=uuid, data=data)

                            # A change was detected
                            if available_detected:

                                rest_and_times = get_restaurants_and_times()
                                date_formatted  = datetime.datetime.strptime(watch['date'], '%Y-%m-%d').date().strftime('%m/%d/%Y')
                                restaurant_name = rest_and_times['restaurants'][watch['restaurant']]
                                search_time = rest_and_times['search_times'][watch['search_time']]

                                n_object = {}
                                print (">> Availability detected in UUID {} - {} - {}".format(uuid, restaurant_name, date_formatted))
                                self.datastore.update_watch(uuid, {"history": {str(curr_date): offers}})


                                dates = list(watch['history'].keys())
                                # Convert to int, sort and back to str again
                                # @todo replace datastore getter that does this automatically
                                dates = [int(i) for i in dates]
                                dates.sort(reverse=True)
                                dates = [str(i) for i in dates]

                                # Did it have any notification alerts to hit?
                                if len(watch['notification_urls']):
                                    print(">>> Notifications queued for UUID from watch {}".format(uuid))
                                    n_object['notification_urls'] = watch['notification_urls']
                                    n_object['notification_title'] = watch['notification_title']
                                    n_object['notification_body'] = watch['notification_body']
                                    n_object['notification_format'] = watch['notification_format']

                                # No? maybe theres a global setting, queue them all
                                elif len(self.datastore.data['settings']['application']['notification_urls']):
                                    print(">>> Watch notification URLs were empty, using GLOBAL notifications for UUID: {}".format(uuid))
                                    n_object['notification_urls'] = self.datastore.data['settings']['application']['notification_urls']
                                    n_object['notification_title'] = self.datastore.data['settings']['application']['notification_title']
                                    n_object['notification_body'] = self.datastore.data['settings']['application']['notification_body']
                                    n_object['notification_format'] = self.datastore.data['settings']['application']['notification_format']
                                else:
                                    print(">>> NO notifications queued, watch and global notification URLs were empty.")

                                # Only prepare to notify if the rules above matched
                                if 'notification_urls' in n_object:

                                    # HTML needs linebreak, but MarkDown and Text can use a linefeed
                                    if n_object['notification_format'] == 'HTML':
                                        line_feed_sep = "</br>"
                                    else:
                                        line_feed_sep = "\n"

                                    # Prepare the offer list
                                    found_reservations = ''
                                    for offer in offers:
                                        found_reservations += "{} - {}{}{}".format(offer['time'], offer['url'], line_feed_sep, line_feed_sep)

                                    n_object.update({
                                        'uuid': uuid,
                                        'restaurant': restaurant_name,
                                        'found_reservations': found_reservations,
                                        'search_date': date_formatted,
                                        'search_time': search_time,
                                        'party_size': watch['party_size']
                                    })

                                    self.notification_q.put(n_object)

                                # Pause search
                                if watch['pause_length'] is not None:
                                    self.datastore.pause_watch(uuid=uuid, pause=watch['pause_length'])
                                elif self.datastore.data['settings']['application']['pause_length'] is not None:
                                    self.datastore.pause_watch(uuid=uuid, pause=self.datastore.data['settings']['application']['pause_length'])


                        except Exception as e:
                            # Catch everything possible here, so that if a worker crashes, we don't lose it until restart!
                            print("!!!! Exception in update_worker !!!\n", e)
                            self.app.logger.error("Exception reached processing watch UUID: %s - %s", uuid, str(e))
                            self.datastore.update_watch(uuid=uuid, data={'last_error': str(e)})

                    finally:
                        # Always record that we atleast tried
                        add_count = self.datastore.data['watching'][uuid]['total_searches'] + 1
                        self.datastore.update_watch(uuid=uuid, data={'fetch_time': round(time.time() - now, 3),
                                                                           'last_checked': round(time.time()),
                                                                           'total_searches': add_count})

                self.current_uuid = None  # Done
                self.q.task_done()

                # Give the CPU time to interrupt
                time.sleep(0.1)

            self.app.config.exit.wait(1)
