-- Run in Supabase > SQL Editor
create extension if not exists pgcrypto;

create table users (
  id uuid primary key default gen_random_uuid(),
  role text not null check (role in ('customer','seller','admin')),
  name text not null,
  phone text unique not null,
  email text unique,
  password_hash text not null,
  address jsonb,               -- {line, city, state, country, pin}
  avatar_key text,             -- R2 key
  status text not null default 'active' check (status in ('active','pending','blocked')),
  created_at timestamptz default now()
);

create table shops (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid unique references users(id) on delete cascade,
  name text not null,
  category text,
  area text,
  logo_key text,
  banner_key text,
  approved boolean default false,
  created_at timestamptz default now()
);

create table products (
  id uuid primary key default gen_random_uuid(),
  shop_id uuid references shops(id) on delete cascade,
  name text not null,
  category text not null,
  brand text,
  price numeric(10,2) not null check (price > 0),
  mrp numeric(10,2),
  colors text[] default '{}',
  stock jsonb not null default '{}',   -- {"S":5,"M":3} or {"default":10}
  image_keys text[] default '{}',      -- R2 keys
  active boolean default true,
  created_at timestamptz default now()
);
create index on products(shop_id);
create index on products(category);

create table orders (
  id uuid primary key default gen_random_uuid(),
  customer_id uuid references users(id),
  shop_id uuid references shops(id),
  status text not null default 'placed'
    check (status in ('placed','confirmed','packed','out_for_delivery','delivered','cancelled','return_requested','returned')),
  items jsonb not null,               -- snapshot [{product_id,name,size,qty,price}]
  subtotal numeric(10,2), discount numeric(10,2) default 0,
  delivery_fee numeric(10,2) default 0, total numeric(10,2),
  commission numeric(10,2) default 0,
  coupon text, address jsonb, payment text default 'cod',
  timeline jsonb default '[]',
  created_at timestamptz default now()
);
create index on orders(customer_id);
create index on orders(shop_id);

create table coupons (
  code text primary key, percent numeric(5,2), max_off numeric(10,2),
  min_order numeric(10,2) default 0, active boolean default true
);
insert into coupons(code,percent,max_off,min_order) values ('MMART10',10,200,300);

create table ads (
  id uuid primary key default gen_random_uuid(),
  title text, image_key text, link text,
  kind text default 'popup' check (kind in ('popup','bottom_sheet')),
  active boolean default true, starts_at timestamptz, ends_at timestamptz,
  created_at timestamptz default now()
);

create table contact_messages (
  id uuid primary key default gen_random_uuid(),
  name text, email text, topic text, message text,
  created_at timestamptz default now()
);

create table settings (key text primary key, value jsonb);
insert into settings values ('platform','{"commission":3,"deliveryFee":49,"freeOver":1500}');

-- Lock tables: only backend (service_role) can touch them
alter table users enable row level security;
alter table shops enable row level security;
alter table products enable row level security;
alter table orders enable row level security;
alter table coupons enable row level security;
alter table ads enable row level security;
alter table contact_messages enable row level security;
alter table settings enable row level security;
