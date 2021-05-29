

CREATE TABLE accounts(
    id SERIAL PRIMARY KEY,
    handle VARCHAR(32) UNIQUE NOT NULL,
    email VARCHAR(300) UNIQUE NOT NULL,
    pw_hash VARCHAR(300) NOT NULL
);


CREATE TABLE posts(
    id BIGSERIAL PRIMARY KEY,
    content VARCHAR(240) NOT NULL,
    author INT NOT NULL,
    post_time BIGINT NOT NULL,
    FOREIGN KEY (author) REFERENCES accounts(id)
);

CREATE TABLE follows(
    follower INT NOT NULL,
    followee INT NOT NULL,
    PRIMARY KEY (follower, followee),
    FOREIGN KEY (follower) REFERENCES accounts(id),
    FOREIGN KEY (followee) REFERENCES accounts(id)
);