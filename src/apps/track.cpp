#include <iostream>
#include <thread>
#include <chrono>
#include <string>
#include <vector>
#include <exception>

#include <libtorrent/session.hpp>
#include <libtorrent/add_torrent_params.hpp>
#include <libtorrent/torrent_handle.hpp>
#include <libtorrent/alert_types.hpp>
#include <libtorrent/magnet_uri.hpp>

int main(int argc, char const* argv[])
{
    lt::settings_pack p;
    // intentionally listing them all so i know what i'm getting....
    lt::alert_category_t alert_flags =
        lt::alert::error_notification |
        lt::alert::peer_notification |
        lt::alert::port_mapping_notification |
        lt::alert::storage_notification |
        lt::alert::tracker_notification |
        lt::alert::connect_notification |
        lt::alert::status_notification |
        lt::alert::ip_block_notification |
        lt::alert::performance_warning |
        lt::alert::dht_notification |
        lt::alert::stats_notification |
        lt::alert::session_log_notification |
        lt::alert::torrent_log_notification |
        lt::alert::peer_log_notification |
        lt::alert::incoming_request_notification |
        lt::alert::dht_log_notification |
        lt::alert::dht_operation_notification |
        lt::alert::port_mapping_log_notification |
        lt::alert::picker_log_notification |
        lt::alert::file_progress_notification |
        lt::alert::piece_progress_notification |
        lt::alert::upload_notification |
        lt::alert::block_progress_notification;
    p.set_int(lt::settings_pack::alert_mask, alert_flags);
    lt::session ses(p);
    lt::add_torrent_params atp;
    atp.info_hash = lt::sha1_hash("43c08ad50d496b64efb7f2a46c90b04fcd1d3b5c");
    atp.trackers = {
        "udp://tracker.leechers-paradise.org:6969",
        "udp://tracker.openbittorrent.com:80",
        "udp://open.demonii.com:1337",
        "udp://tracker.coppersurfer.tk:6969",
        "udp://exodus.desync.com:6969",
    };
    atp.flags = lt::torrent_flags::update_subscribe |
                lt::torrent_flags::upload_mode;
    ses.add_torrent(std::move(atp));
    std::atomic_bool run(true);
    for (;run.load();) {
        std::vector<lt::alert*> alerts;
        ses.pop_alerts(&alerts);

        for (lt::alert const* a : alerts) {
            switch (a->type()) {
            case lt::torrent_added_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::torrent_added_alert*>(a);
                break;
            }
            case lt::torrent_removed_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::torrent_removed_alert*>(a);
                break;
            }
            case lt::read_piece_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::read_piece_alert*>(a);
                break;
            }
            case lt::file_completed_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::file_completed_alert*>(a);
                break;
            }
            case lt::file_renamed_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::file_renamed_alert*>(a);
                break;
            }
            case lt::file_rename_failed_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::file_rename_failed_alert*>(a);
                break;
            }
            case lt::performance_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::performance_alert*>(a);
                break;
            }
            case lt::state_changed_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::state_changed_alert*>(a);
                break;
            }
            case lt::tracker_error_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::tracker_error_alert*>(a);
                break;
            }
            case lt::tracker_warning_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::tracker_warning_alert*>(a);
                break;
            }
            case lt::scrape_reply_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::scrape_reply_alert*>(a);
                break;
            }
            case lt::scrape_failed_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::scrape_failed_alert*>(a);
                break;
            }
            case lt::tracker_reply_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::tracker_reply_alert*>(a);
                break;
            }
            case lt::dht_reply_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::dht_reply_alert*>(a);
                break;
            }
            case lt::tracker_announce_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::tracker_announce_alert*>(a);
                break;
            }
            case lt::hash_failed_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::hash_failed_alert*>(a);
                break;
            }
            case lt::peer_ban_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::peer_ban_alert*>(a);
                break;
            }
            case lt::peer_unsnubbed_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::peer_unsnubbed_alert*>(a);
                break;
            }
            case lt::peer_snubbed_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::peer_snubbed_alert*>(a);
                break;
            }
            case lt::peer_error_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::peer_error_alert*>(a);
                break;
            }
            case lt::peer_connect_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::peer_connect_alert*>(a);
                break;
            }
            case lt::peer_disconnected_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::peer_disconnected_alert*>(a);
                break;
            }
            case lt::invalid_request_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::invalid_request_alert*>(a);
                break;
            }
            case lt::torrent_finished_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::torrent_finished_alert*>(a);
                break;
            }
            case lt::piece_finished_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::piece_finished_alert*>(a);
                break;
            }
            case lt::request_dropped_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::request_dropped_alert*>(a);
                break;
            }
            case lt::block_timeout_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::block_timeout_alert*>(a);
                break;
            }
            case lt::block_finished_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::block_finished_alert*>(a);
                break;
            }
            case lt::block_downloading_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::block_downloading_alert*>(a);
                break;
            }
            case lt::unwanted_block_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::unwanted_block_alert*>(a);
                break;
            }
            case lt::storage_moved_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::storage_moved_alert*>(a);
                break;
            }
            case lt::storage_moved_failed_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::storage_moved_failed_alert*>(a);
                break;
            }
            case lt::torrent_deleted_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::torrent_deleted_alert*>(a);
                break;
            }
            case lt::torrent_delete_failed_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::torrent_delete_failed_alert*>(a);
                break;
            }
            case lt::save_resume_data_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::save_resume_data_alert*>(a);
                break;
            }
            case lt::save_resume_data_failed_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::save_resume_data_failed_alert*>(a);
                break;
            }
            case lt::torrent_paused_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::torrent_paused_alert*>(a);
                break;
            }
            case lt::torrent_resumed_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::torrent_resumed_alert*>(a);
                break;
            }
            case lt::torrent_checked_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::torrent_checked_alert*>(a);
                break;
            }
            case lt::url_seed_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::url_seed_alert*>(a);
                break;
            }
            case lt::file_error_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::file_error_alert*>(a);
                break;
            }
            case lt::metadata_failed_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::metadata_failed_alert*>(a);
                break;
            }
            case lt::metadata_received_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::metadata_received_alert*>(a);
                break;
            }
            case lt::udp_error_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::udp_error_alert*>(a);
                break;
            }
            case lt::external_ip_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::external_ip_alert*>(a);
                break;
            }
            case lt::listen_failed_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::listen_failed_alert*>(a);
                break;
            }
            case lt::listen_succeeded_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::listen_succeeded_alert*>(a);
                break;
            }
            case lt::portmap_error_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::portmap_error_alert*>(a);
                break;
            }
            case lt::portmap_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::portmap_alert*>(a);
                break;
            }
            case lt::portmap_log_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::portmap_log_alert*>(a);
                break;
            }
            case lt::fastresume_rejected_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::fastresume_rejected_alert*>(a);
                break;
            }
            case lt::peer_blocked_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::peer_blocked_alert*>(a);
                break;
            }
            case lt::dht_announce_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::dht_announce_alert*>(a);
                break;
            }
            case lt::dht_get_peers_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::dht_get_peers_alert*>(a);
                break;
            }
            case lt::stats_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::stats_alert*>(a);
                break;
            }
            case lt::cache_flushed_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::cache_flushed_alert*>(a);
                break;
            }
            case lt::lsd_peer_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::lsd_peer_alert*>(a);
                break;
            }
            case lt::trackerid_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::trackerid_alert*>(a);
                break;
            }
            case lt::dht_bootstrap_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::dht_bootstrap_alert*>(a);
                break;
            }
            case lt::torrent_error_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::torrent_error_alert*>(a);
                break;
            }
            case lt::torrent_need_cert_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::peer_snubbed_alert*>(a);
                break;
            }
            case lt::incoming_connection_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::incoming_connection_alert*>(a);
                break;
            }
            case lt::add_torrent_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::add_torrent_alert*>(a);
                break;
            }
            case lt::state_update_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::state_update_alert*>(a);
                break;
            }
            case lt::session_stats_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::session_stats_alert*>(a);
                break;
            }
            case lt::dht_error_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::dht_error_alert*>(a);
                break;
            }
            case lt::dht_immutable_item_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::dht_immutable_item_alert*>(a);
                break;
            }
            case lt::dht_mutable_item_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::dht_mutable_item_alert*>(a);
                break;
            }
            case lt::dht_put_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::dht_put_alert*>(a);
                break;
            }
            case lt::i2p_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::i2p_alert*>(a);
                break;
            }
            case lt::dht_outgoing_get_peers_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::dht_outgoing_get_peers_alert*>(a);
                break;
            }
            case lt::log_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::log_alert*>(a);
                break;
            }
            case lt::torrent_log_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::torrent_log_alert*>(a);
                break;
            }
            case lt::peer_log_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::peer_log_alert*>(a);
                break;
            }
            case lt::lsd_error_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::lsd_error_alert*>(a);
                break;
            }
            case lt::dht_stats_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::dht_stats_alert*>(a);
                break;
            }
            case lt::incoming_request_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::incoming_request_alert*>(a);
                break;
            }
            case lt::dht_log_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::dht_log_alert*>(a);
                break;
            }
            case lt::dht_pkt_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::dht_pkt_alert*>(a);
                break;
            }
            case lt::dht_get_peers_reply_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::dht_get_peers_reply_alert*>(a);
                break;
            }
            case lt::dht_direct_response_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::dht_direct_response_alert*>(a);
                break;
            }
            case lt::picker_log_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::picker_log_alert*>(a);
                break;
            }
            case lt::session_error_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::session_error_alert*>(a);
                break;
            }
            case lt::dht_live_nodes_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::dht_live_nodes_alert*>(a);
                break;
            }
            case lt::session_stats_header_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::session_stats_header_alert*>(a);
                break;
            }
            case lt::dht_sample_infohashes_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::dht_sample_infohashes_alert*>(a);
                break;
            }
            case lt::block_uploaded_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::block_uploaded_alert*>(a);
                break;
            }
            case lt::alerts_dropped_alert::alert_type:
            {
                auto ax = dynamic_cast<const lt::alerts_dropped_alert*>(a);
                break;
            }
            default:
                std::cerr << a << std::endl;
                std::cerr << a->type() << std::endl;
                std::cerr << a->message() << std::endl;
                std::cerr << a->what() << std::endl;
                run.store(false);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    return 0;
}

#ifdef I_DONT_HATE_EXCEPTIONS
    const char *magnet_uri = argc > 1 ? argv[1] : ("magnet:?xt=urn:btih:43c08ad50d496b64efb7f2a46c90b04fcd1d3b5c&"
                                              "dn=The%20Amazing%20Race%20Season%201%20-%2030&"
                                              "tr=udp%3A%2F%2Ftracker.leechers-paradise.org%3A6969"
                                              "&tr=udp%3A%2F%2Ftracker.openbittorrent.com%3A80"
                                              "&tr=udp%3A%2F%2Fopen.demonii.com%3A1337"
                                              "&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969"
                                                   "&tr=udp%3A%2F%2Fexodus.desync.com%3A6969");
    if (argc != 2) {
        std::cerr << "usage: " << argv[0] << " [<magnet-url>]" << std::endl;
        //    return 1;
    }
    lt::settings_pack p;
    p.set_int(lt::settings_pack::alert_mask, lt::alert::status_notification
                                                 | lt::alert::error_notification);

    lt::session ses(p);

    lt::add_torrent_params atp = lt::parse_magnet_uri(magnet_uri);
    atp.save_path = "."; // save in current dir
    lt::torrent_handle h = ses.add_torrent(std::move(atp));

    for (;;) {
        std::vector<lt::alert*> alerts;
        ses.pop_alerts(&alerts);

        for (lt::alert const* a : alerts) {
            std::cout << a->message() << std::endl;
            // if we receive the finished alert or an error, we're done
            if (lt::alert_cast<lt::torrent_finished_alert>(a)) {
                goto done;
            }
            if (lt::alert_cast<lt::torrent_error_alert>(a)) {
                goto done;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
done:
    std::cout << "done, shutting down" << std::endl;
}
catch (std::exception& e)
{
    std::cerr << "Error: " << e.what() << std::endl;
}
#endif
