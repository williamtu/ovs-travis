void other_conn_update_expiration(struct conntrack *ct, struct conn *conn,
                             enum ct_timeout tm, long long now);
void other_conn_init_expiration(struct conntrack *ct, struct conn *conn,
                             enum ct_timeout tm, long long now);

