--
-- PostgreSQL database dump
--

-- Dumped from database version 12.9 (Ubuntu 12.9-0ubuntu0.20.04.1)
-- Dumped by pg_dump version 12.9 (Ubuntu 12.9-0ubuntu0.20.04.1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: hostdata; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.hostdata (
    pk integer NOT NULL,
    "timestamp" timestamp without time zone,
    totalram integer,
    usedram integer,
    cpupercent numeric,
    cputemp numeric,
    cpuvolts numeric,
    totaltasks integer,
    runningtasks integer,
    sleepingtasks integer,
    stoppedtasks integer,
    zombietasks integer,
    mac character varying,
    label integer
);


ALTER TABLE public.hostdata OWNER TO postgres;

--
-- Name: hostdata_pk_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.hostdata_pk_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.hostdata_pk_seq OWNER TO postgres;

--
-- Name: hostdata_pk_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.hostdata_pk_seq OWNED BY public.hostdata.pk;


--
-- Name: networkdata; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.networkdata (
    pk integer NOT NULL,
    "timestamp" timestamp without time zone,
    smac character varying(17),
    dmac character varying(17),
    sip character varying(15),
    dip character varying(15),
    sport integer,
    dport integer,
    ttl integer,
    tos integer,
    id integer,
    ihl integer,
    dlen integer,
    proto integer,
    label integer
);


ALTER TABLE public.networkdata OWNER TO postgres;

--
-- Name: networkdata_pk_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.networkdata_pk_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.networkdata_pk_seq OWNER TO postgres;

--
-- Name: networkdata_pk_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.networkdata_pk_seq OWNED BY public.networkdata.pk;


--
-- Name: hostdata pk; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.hostdata ALTER COLUMN pk SET DEFAULT nextval('public.hostdata_pk_seq'::regclass);


--
-- Name: networkdata pk; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.networkdata ALTER COLUMN pk SET DEFAULT nextval('public.networkdata_pk_seq'::regclass);


--
-- Data for Name: hostdata; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.hostdata (pk, "timestamp", totalram, usedram, cpupercent, cputemp, cpuvolts, totaltasks, runningtasks, sleepingtasks, stoppedtasks, zombietasks, mac, label) FROM stdin;
\.


--
-- Data for Name: networkdata; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.networkdata (pk, "timestamp", smac, dmac, sip, dip, sport, dport, ttl, tos, id, ihl, dlen, proto, label) FROM stdin;
\.


--
-- Name: hostdata_pk_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.hostdata_pk_seq', 225950, true);


--
-- Name: networkdata_pk_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.networkdata_pk_seq', 459454, true);


--
-- Name: hostdata hostdata_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.hostdata
    ADD CONSTRAINT hostdata_pkey PRIMARY KEY (pk);


--
-- Name: networkdata networkdata_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.networkdata
    ADD CONSTRAINT networkdata_pkey PRIMARY KEY (pk);


--
-- PostgreSQL database dump complete
--

