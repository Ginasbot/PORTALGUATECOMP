DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS categories;
DROP TABLE IF EXISTS users;
CREATE TABLE roles (
id INTEGER PRIMARY KEY NOT NULL,
    roles_name TEXT NOT NULL
);

CREATE TABLE categories (
id INTEGER PRIMARY KEY NOT NULL,
    category_name TEXT NOT NULL
);

CREATE TABLE users (
user_id INTEGER PRIMARY KEY NOT NULL,
    first_name TEXT NOT NULL,
       last_name TEXT NOT NULL,
          email TEXT NOT NULL,
             password TEXT NOT NULL,
                role TEXT NOT NULL,
                   date_added datetime default current_timestamp,
                       date_modified datetime default current_timestamp
);


