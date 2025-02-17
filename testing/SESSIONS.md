# sessions

## Local PostgreSQL
```sql
SELECT clients.client_id,
       sessions.offline_flag,
       to_char(to_timestamp(sessions.min_start),'Mon-dd hh24:MI') AS min_start,
       to_char(to_timestamp(sessions.min_start+clients.client_session_idle_timeout),'Mon-dd hh24:MI') AS min_end,
       to_char(to_timestamp(sessions.max_start),'Mon-dd hh24:MI') AS max_start,
       to_char(to_timestamp(sessions.max_start+clients.client_session_idle_timeout),'Mon-dd hh24:MI') AS max_end,
       sessions.cantidad
FROM (select offline_client_session.client_id,
             offline_user_session.offline_flag,
             min(offline_client_session.timestamp) AS min_start,
             max(offline_client_session.timestamp) AS max_start,
             count(1) AS cantidad
        from offline_client_session
        join offline_user_session on offline_client_session.user_session_id=offline_user_session.user_session_id
    GROUP BY offline_client_session.client_id, offline_user_session.offline_flag) sessions
JOIN (SELECT client.id, client.client_id, CAST(client_attributes.value as INTEGER) AS client_session_idle_timeout
        FROM client
        JOIN CLIENT_ATTRIBUTES ON client.id=client_attributes.CLIENT_ID AND client_attributes.name='client.session.idle.timeout'
       WHERE client.REALM_ID='testrealm'
         AND client.client_id LIKE 'ropc%') clients ON sessions.client_id=clients.id
ORDER BY 1
```
