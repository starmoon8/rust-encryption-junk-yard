-- up
CREATE TABLE posts (
    id SERIAL PRIMARY KEY,
    thread_id BIGINT NOT NULL,
    bump_timestamp BIGINT NOT NULL,
    name VARCHAR(255) NOT NULL,
    subject VARCHAR(255),
    message TEXT,
    filename VARCHAR(255),
    thumbname VARCHAR(255),
    time VARCHAR(255) NOT NULL
);