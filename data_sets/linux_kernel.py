import datetime, time

def process_linux_data_set():
    print("Linux Kernel GIT Repository ...");
    print("Extracting group membership changes ...");


    authors = set()
    ops = []
    mem = []

    # read git trace
    with open("linux_kernel_git/linux_kernel_git_revlog.csv", 'r') as f:
        # skip first row
        line = f.readline()
        while line:
            line = f.readline()
            if line:
                items = line.split(',')
                if len(items) == 8:
                    time = float(items[0])
                    if time != 1:
                        authorId = items[7].strip()
                        ops.append((time, authorId))
                        authors.add(authorId)

    print("Total check-ins : ", len(ops))
    ops.sort(key = lambda x: x[0])
    seen_before = set()
    last_seen = {}

    # sort by disretized time, collect date when user was first and last seen
    for (t, u) in ops:
        last_seen[u] = t
        if u not in seen_before:
            seen_before.add(u)
            mem.append(('add', t, u))

    # compute monthly revocations
    monthly_revoke = {}
    for u in last_seen:
        dt = datetime.datetime.fromtimestamp(last_seen[u])
        k_month = dt.strftime("%Y%m")
        if k_month in monthly_revoke:
            monthly_revoke[k_month] += 1
        else:
            monthly_revoke[k_month] = 1

    # compute monthly statistics
    monthly_add = {}
    for (o, t, u) in mem:
        dt = datetime.datetime.fromtimestamp(t)
        k_month = dt.strftime("%Y%m")
        if k_month in monthly_add:
            monthly_add[k_month] += 1
        else:
            monthly_add[k_month] = 1

    # show daily stats
    for k in sorted(monthly_add.iterkeys()):
        a = monthly_add[k]
        r = 0
        if k in monthly_revoke:
            r = monthly_revoke[k]
        #print(k + "," + str(a) + "," + str(r))

    print("Unique authors : ", len(authors));
    print("Seen Before : ", len(seen_before));
    diff = authors.difference(seen_before)
    print(diff)
    print("Processing finished.");

if __name__ == "__main__":
    process_linux_data_set()
