.class public final Llyiahf/vczjk/x01;
.super Llyiahf/vczjk/y86;
.source "SourceFile"


# instance fields
.field public final OooOOo:Llyiahf/vczjk/ld9;

.field public final OooOOo0:Llyiahf/vczjk/wt1;

.field public final OooOOoo:Z

.field public OooOo0:Llyiahf/vczjk/rr0;

.field public final OooOo00:Llyiahf/vczjk/d59;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/wt1;Llyiahf/vczjk/ld9;ZLlyiahf/vczjk/d59;)V
    .locals 2

    const/4 v0, 0x4

    const/4 v1, -0x1

    invoke-direct {p0, v0, v1}, Llyiahf/vczjk/y86;-><init>(II)V

    if-eqz p1, :cond_2

    if-eqz p2, :cond_1

    if-eqz p4, :cond_0

    iput-object p1, p0, Llyiahf/vczjk/x01;->OooOOo0:Llyiahf/vczjk/wt1;

    iput-object p2, p0, Llyiahf/vczjk/x01;->OooOOo:Llyiahf/vczjk/ld9;

    iput-boolean p3, p0, Llyiahf/vczjk/x01;->OooOOoo:Z

    iput-object p4, p0, Llyiahf/vczjk/x01;->OooOo00:Llyiahf/vczjk/d59;

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/x01;->OooOo0:Llyiahf/vczjk/rr0;

    return-void

    :cond_0
    new-instance p1, Ljava/lang/NullPointerException;

    const-string p2, "throwsList == null"

    invoke-direct {p1, p2}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    new-instance p1, Ljava/lang/NullPointerException;

    const-string p2, "code == null"

    invoke-direct {p1, p2}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    new-instance p1, Ljava/lang/NullPointerException;

    const-string p2, "ref == null"

    invoke-direct {p1, p2}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p1
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/rj5;I)V
    .locals 10

    new-instance p2, Llyiahf/vczjk/sw7;

    iget-object p1, p1, Llyiahf/vczjk/bc8;->OooO0O0:Llyiahf/vczjk/t92;

    const/16 v0, 0x8

    invoke-direct {p2, p1, v0}, Llyiahf/vczjk/sw7;-><init>(Ljava/lang/Object;I)V

    iget-object v0, p0, Llyiahf/vczjk/x01;->OooOOo:Llyiahf/vczjk/ld9;

    iget-object v1, v0, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/zk2;

    iget-object v1, v1, Llyiahf/vczjk/zk2;->OooOOo:Ljava/lang/Object;

    check-cast v1, Ljava/util/ArrayList;

    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_0
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_2

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/aw1;

    instance-of v3, v2, Llyiahf/vczjk/ot1;

    if-eqz v3, :cond_0

    check-cast v2, Llyiahf/vczjk/ot1;

    iget-object v3, v2, Llyiahf/vczjk/ot1;->OooO0o0:Llyiahf/vczjk/hj1;

    invoke-virtual {p2, v3}, Llyiahf/vczjk/sw7;->OooOO0o(Llyiahf/vczjk/hj1;)I

    move-result v4

    if-ltz v4, :cond_1

    invoke-virtual {v2, v4}, Llyiahf/vczjk/ot1;->OooOOOO(I)V

    :cond_1
    instance-of v4, v3, Llyiahf/vczjk/vt1;

    if-eqz v4, :cond_0

    check-cast v3, Llyiahf/vczjk/vt1;

    iget-object v3, v3, Llyiahf/vczjk/vt1;->OooOOO0:Llyiahf/vczjk/au1;

    invoke-virtual {p2, v3}, Llyiahf/vczjk/sw7;->OooOO0o(Llyiahf/vczjk/hj1;)I

    move-result v3

    if-ltz v3, :cond_0

    invoke-virtual {v2, v3}, Llyiahf/vczjk/ot1;->OooOOO(I)V

    goto :goto_0

    :cond_2
    iget-object p2, p0, Llyiahf/vczjk/x01;->OooOo0:Llyiahf/vczjk/rr0;

    const/4 v1, 0x0

    if-eqz p2, :cond_a

    invoke-virtual {p2}, Llyiahf/vczjk/rr0;->OooO0oo()V

    iget-object p1, p1, Llyiahf/vczjk/t92;->OooO0o:Llyiahf/vczjk/ce7;

    iget-object v2, p2, Llyiahf/vczjk/rr0;->OooOOOo:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/tr0;

    iget-object v2, v2, Llyiahf/vczjk/x13;->OooOOO:[Ljava/lang/Object;

    array-length v2, v2

    new-instance v3, Ljava/util/TreeMap;

    invoke-direct {v3}, Ljava/util/TreeMap;-><init>()V

    iput-object v3, p2, Llyiahf/vczjk/rr0;->OooOOo:Ljava/lang/Object;

    move v3, v1

    :goto_1
    if-ge v3, v2, :cond_3

    iget-object v4, p2, Llyiahf/vczjk/rr0;->OooOOo:Ljava/lang/Object;

    check-cast v4, Ljava/util/TreeMap;

    iget-object v5, p2, Llyiahf/vczjk/rr0;->OooOOOo:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/tr0;

    invoke-virtual {v5, v3}, Llyiahf/vczjk/x13;->OooO0o0(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/sr0;

    iget-object v5, v5, Llyiahf/vczjk/sr0;->OooOOOO:Llyiahf/vczjk/qr0;

    const/4 v6, 0x0

    invoke-virtual {v4, v5, v6}, Ljava/util/TreeMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    add-int/lit8 v3, v3, 0x1

    goto :goto_1

    :cond_3
    iget-object v2, p2, Llyiahf/vczjk/rr0;->OooOOo:Ljava/lang/Object;

    check-cast v2, Ljava/util/TreeMap;

    invoke-virtual {v2}, Ljava/util/TreeMap;->size()I

    move-result v2

    const v3, 0xffff

    if-gt v2, v3, :cond_9

    new-instance v2, Llyiahf/vczjk/ol0;

    invoke-direct {v2}, Llyiahf/vczjk/ol0;-><init>()V

    iget-object v3, p2, Llyiahf/vczjk/rr0;->OooOOo:Ljava/lang/Object;

    check-cast v3, Ljava/util/TreeMap;

    invoke-virtual {v3}, Ljava/util/TreeMap;->size()I

    move-result v3

    invoke-virtual {v2, v3}, Llyiahf/vczjk/ol0;->OooOOO0(I)I

    move-result v3

    iput v3, p2, Llyiahf/vczjk/rr0;->OooOOO:I

    iget-object v3, p2, Llyiahf/vczjk/rr0;->OooOOo:Ljava/lang/Object;

    check-cast v3, Ljava/util/TreeMap;

    invoke-virtual {v3}, Ljava/util/TreeMap;->entrySet()Ljava/util/Set;

    move-result-object v3

    invoke-interface {v3}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :cond_4
    :goto_2
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_8

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/util/Map$Entry;

    invoke-interface {v4}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/qr0;

    iget-object v6, v5, Llyiahf/vczjk/x13;->OooOOO:[Ljava/lang/Object;

    array-length v7, v6

    array-length v6, v6

    if-nez v6, :cond_5

    move v6, v1

    goto :goto_3

    :cond_5
    add-int/lit8 v6, v6, -0x1

    invoke-virtual {v5, v6}, Llyiahf/vczjk/x13;->OooO0o0(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/pr0;

    sget-object v8, Llyiahf/vczjk/au1;->OooOOOO:Llyiahf/vczjk/au1;

    iget-object v6, v6, Llyiahf/vczjk/pr0;->OooOOO0:Llyiahf/vczjk/au1;

    invoke-virtual {v6, v8}, Llyiahf/vczjk/au1;->equals(Ljava/lang/Object;)Z

    move-result v6

    :goto_3
    iget v8, v2, Llyiahf/vczjk/ol0;->OooO0OO:I

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    invoke-interface {v4, v8}, Ljava/util/Map$Entry;->setValue(Ljava/lang/Object;)Ljava/lang/Object;

    if-eqz v6, :cond_6

    add-int/lit8 v4, v7, -0x1

    neg-int v4, v4

    invoke-virtual {v2, v4}, Llyiahf/vczjk/ol0;->OooOO0o(I)V

    add-int/lit8 v7, v7, -0x1

    goto :goto_4

    :cond_6
    invoke-virtual {v2, v7}, Llyiahf/vczjk/ol0;->OooOO0o(I)V

    :goto_4
    move v4, v1

    :goto_5
    if-ge v4, v7, :cond_7

    invoke-virtual {v5, v4}, Llyiahf/vczjk/x13;->OooO0o0(I)Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/pr0;

    iget-object v9, v8, Llyiahf/vczjk/pr0;->OooOOO0:Llyiahf/vczjk/au1;

    invoke-virtual {p1, v9}, Llyiahf/vczjk/ce7;->OooOOO0(Llyiahf/vczjk/au1;)I

    move-result v9

    invoke-virtual {v2, v9}, Llyiahf/vczjk/ol0;->OooOOO0(I)I

    iget v8, v8, Llyiahf/vczjk/pr0;->OooOOO:I

    invoke-virtual {v2, v8}, Llyiahf/vczjk/ol0;->OooOOO0(I)I

    add-int/lit8 v4, v4, 0x1

    goto :goto_5

    :cond_7
    if-eqz v6, :cond_4

    invoke-virtual {v5, v7}, Llyiahf/vczjk/x13;->OooO0o0(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/pr0;

    iget v4, v4, Llyiahf/vczjk/pr0;->OooOOO:I

    invoke-virtual {v2, v4}, Llyiahf/vczjk/ol0;->OooOOO0(I)I

    goto :goto_2

    :cond_8
    iget p1, v2, Llyiahf/vczjk/ol0;->OooO0OO:I

    new-array v3, p1, [B

    iget-object v2, v2, Llyiahf/vczjk/ol0;->OooO0O0:[B

    invoke-static {v2, v1, v3, v1, p1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    iput-object v3, p2, Llyiahf/vczjk/rr0;->OooOOo0:Ljava/io/Serializable;

    iget-object p1, p0, Llyiahf/vczjk/x01;->OooOo0:Llyiahf/vczjk/rr0;

    invoke-virtual {p1}, Llyiahf/vczjk/rr0;->OooO0oo()V

    iget-object p2, p1, Llyiahf/vczjk/rr0;->OooOOOo:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/tr0;

    iget-object p2, p2, Llyiahf/vczjk/x13;->OooOOO:[Ljava/lang/Object;

    array-length p2, p2

    mul-int/lit8 p2, p2, 0x8

    iget-object p1, p1, Llyiahf/vczjk/rr0;->OooOOo0:Ljava/io/Serializable;

    check-cast p1, [B

    array-length p1, p1

    add-int v1, p2, p1

    goto :goto_6

    :cond_9
    new-instance p1, Ljava/lang/UnsupportedOperationException;

    const-string p2, "too many catch handlers"

    invoke-direct {p1, p2}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_a
    :goto_6
    invoke-virtual {v0}, Llyiahf/vczjk/ld9;->Oooo()V

    iget-object p1, v0, Llyiahf/vczjk/ld9;->OooOOo0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/bw1;

    invoke-virtual {p1}, Llyiahf/vczjk/bw1;->OooO0oo()I

    move-result p1

    and-int/lit8 p2, p1, 0x1

    if-eqz p2, :cond_b

    add-int/lit8 p1, p1, 0x1

    :cond_b
    mul-int/lit8 p1, p1, 0x2

    add-int/lit8 p1, p1, 0x10

    add-int/2addr p1, v1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/y86;->OooOO0(I)V

    return-void
.end method

.method public final OooO00o(Llyiahf/vczjk/t92;)V
    .locals 11

    iget-object v0, p1, Llyiahf/vczjk/t92;->OooOO0o:Llyiahf/vczjk/rj5;

    iget-object v0, p0, Llyiahf/vczjk/x01;->OooOOo:Llyiahf/vczjk/ld9;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v1, v0, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/zk2;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v1, v0, Llyiahf/vczjk/ld9;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ed5;

    iget-object v1, v1, Llyiahf/vczjk/ed5;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ed5;

    iget-object v1, v1, Llyiahf/vczjk/ed5;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/j90;

    iget-object v2, v1, Llyiahf/vczjk/x13;->OooOOO:[Ljava/lang/Object;

    array-length v2, v2

    const/4 v3, 0x0

    move v4, v3

    :goto_0
    const/16 v5, 0x14

    if-ge v4, v2, :cond_4

    invoke-virtual {v1, v4}, Llyiahf/vczjk/x13;->OooO0o0(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/i90;

    iget-object v6, v6, Llyiahf/vczjk/i90;->OooO0O0:Llyiahf/vczjk/h14;

    invoke-virtual {v6}, Llyiahf/vczjk/h14;->OooO0oo()Llyiahf/vczjk/g14;

    move-result-object v6

    invoke-virtual {v6}, Llyiahf/vczjk/g14;->OooO0Oo()Llyiahf/vczjk/n4a;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/x13;

    iget-object v6, v6, Llyiahf/vczjk/x13;->OooOOO:[Ljava/lang/Object;

    array-length v6, v6

    if-eqz v6, :cond_3

    iget-object v1, v0, Llyiahf/vczjk/ld9;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ed5;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v2, Ljava/util/HashSet;

    invoke-direct {v2, v5}, Ljava/util/HashSet;-><init>(I)V

    iget-object v1, v1, Llyiahf/vczjk/ed5;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ed5;

    iget-object v1, v1, Llyiahf/vczjk/ed5;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/j90;

    iget-object v4, v1, Llyiahf/vczjk/x13;->OooOOO:[Ljava/lang/Object;

    array-length v4, v4

    move v6, v3

    :goto_1
    if-ge v6, v4, :cond_1

    invoke-virtual {v1, v6}, Llyiahf/vczjk/x13;->OooO0o0(I)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/i90;

    iget-object v7, v7, Llyiahf/vczjk/i90;->OooO0O0:Llyiahf/vczjk/h14;

    invoke-virtual {v7}, Llyiahf/vczjk/h14;->OooO0oo()Llyiahf/vczjk/g14;

    move-result-object v7

    invoke-virtual {v7}, Llyiahf/vczjk/g14;->OooO0Oo()Llyiahf/vczjk/n4a;

    move-result-object v7

    move-object v8, v7

    check-cast v8, Llyiahf/vczjk/x13;

    iget-object v8, v8, Llyiahf/vczjk/x13;->OooOOO:[Ljava/lang/Object;

    array-length v8, v8

    move v9, v3

    :goto_2
    if-ge v9, v8, :cond_0

    invoke-interface {v7, v9}, Llyiahf/vczjk/n4a;->OooO0O0(I)Llyiahf/vczjk/p1a;

    move-result-object v10

    invoke-virtual {v2, v10}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    add-int/lit8 v9, v9, 0x1

    goto :goto_2

    :cond_0
    add-int/lit8 v6, v6, 0x1

    goto :goto_1

    :cond_1
    invoke-virtual {v2}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_3
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_2

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/p1a;

    iget-object v3, p1, Llyiahf/vczjk/t92;->OooO0o:Llyiahf/vczjk/ce7;

    invoke-virtual {v3, v2}, Llyiahf/vczjk/ce7;->OooOOo0(Llyiahf/vczjk/p1a;)V

    goto :goto_3

    :cond_2
    new-instance v1, Llyiahf/vczjk/rr0;

    invoke-direct {v1, v0}, Llyiahf/vczjk/rr0;-><init>(Llyiahf/vczjk/ld9;)V

    iput-object v1, p0, Llyiahf/vczjk/x01;->OooOo0:Llyiahf/vczjk/rr0;

    goto :goto_4

    :cond_3
    add-int/lit8 v4, v4, 0x1

    goto :goto_0

    :cond_4
    :goto_4
    iget-object v0, v0, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/zk2;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Ljava/util/HashSet;

    invoke-direct {v1, v5}, Ljava/util/HashSet;-><init>(I)V

    iget-object v0, v0, Llyiahf/vczjk/zk2;->OooOOo:Ljava/lang/Object;

    check-cast v0, Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_5
    :goto_5
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_8

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/aw1;

    instance-of v3, v2, Llyiahf/vczjk/ot1;

    if-eqz v3, :cond_6

    check-cast v2, Llyiahf/vczjk/ot1;

    iget-object v2, v2, Llyiahf/vczjk/ot1;->OooO0o0:Llyiahf/vczjk/hj1;

    invoke-virtual {v1, v2}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    goto :goto_5

    :cond_6
    instance-of v3, v2, Llyiahf/vczjk/a45;

    if-nez v3, :cond_7

    instance-of v3, v2, Llyiahf/vczjk/b45;

    if-eqz v3, :cond_5

    check-cast v2, Llyiahf/vczjk/b45;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    goto :goto_5

    :cond_7
    check-cast v2, Llyiahf/vczjk/a45;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p1, 0x0

    throw p1

    :cond_8
    invoke-virtual {v1}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_6
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_9

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/hj1;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/t92;->OooO00o(Llyiahf/vczjk/hj1;)V

    goto :goto_6

    :cond_9
    return-void
.end method

.method public final OooO0O0()Llyiahf/vczjk/i54;
    .locals 1

    sget-object v0, Llyiahf/vczjk/i54;->OooOo0o:Llyiahf/vczjk/i54;

    return-object v0
.end method

.method public final OooOO0O(Llyiahf/vczjk/t92;Llyiahf/vczjk/ol0;)V
    .locals 16

    move-object/from16 v1, p0

    move-object/from16 v0, p2

    invoke-virtual {v0}, Llyiahf/vczjk/ol0;->OooO0Oo()Z

    move-result v2

    iget-object v3, v1, Llyiahf/vczjk/x01;->OooOOo:Llyiahf/vczjk/ld9;

    invoke-virtual {v3}, Llyiahf/vczjk/ld9;->Oooo()V

    iget-object v4, v3, Llyiahf/vczjk/ld9;->OooOOo0:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/bw1;

    iget v4, v4, Llyiahf/vczjk/bw1;->OooOOOO:I

    invoke-virtual {v3}, Llyiahf/vczjk/ld9;->Oooo()V

    iget-object v5, v3, Llyiahf/vczjk/ld9;->OooOOo0:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/bw1;

    iget-object v6, v5, Llyiahf/vczjk/x13;->OooOOO:[Ljava/lang/Object;

    array-length v6, v6

    const/4 v7, 0x0

    move v8, v7

    move v9, v8

    :goto_0
    const/4 v10, 0x1

    if-ge v8, v6, :cond_3

    invoke-virtual {v5, v8}, Llyiahf/vczjk/x13;->OooO0o0(I)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Llyiahf/vczjk/aw1;

    instance-of v12, v11, Llyiahf/vczjk/ot1;

    if-eqz v12, :cond_2

    move-object v12, v11

    check-cast v12, Llyiahf/vczjk/ot1;

    iget-object v12, v12, Llyiahf/vczjk/ot1;->OooO0o0:Llyiahf/vczjk/hj1;

    instance-of v13, v12, Llyiahf/vczjk/wt1;

    if-eqz v13, :cond_1

    check-cast v12, Llyiahf/vczjk/wt1;

    iget-object v11, v11, Llyiahf/vczjk/aw1;->OooO00o:Llyiahf/vczjk/od2;

    iget v11, v11, Llyiahf/vczjk/od2;->OooO0O0:I

    const/16 v13, 0x71

    if-ne v11, v13, :cond_0

    goto :goto_1

    :cond_0
    move v10, v7

    :goto_1
    invoke-virtual {v12, v10}, Llyiahf/vczjk/wt1;->OooO0o(Z)I

    move-result v10

    goto :goto_2

    :cond_1
    move v10, v7

    :goto_2
    if-le v10, v9, :cond_2

    move v9, v10

    :cond_2
    add-int/lit8 v8, v8, 0x1

    goto :goto_0

    :cond_3
    iget-object v5, v1, Llyiahf/vczjk/x01;->OooOOo0:Llyiahf/vczjk/wt1;

    iget-boolean v6, v1, Llyiahf/vczjk/x01;->OooOOoo:Z

    invoke-virtual {v5, v6}, Llyiahf/vczjk/wt1;->OooO0o(Z)I

    move-result v6

    invoke-virtual {v3}, Llyiahf/vczjk/ld9;->Oooo()V

    iget-object v8, v3, Llyiahf/vczjk/ld9;->OooOOo0:Ljava/lang/Object;

    check-cast v8, Llyiahf/vczjk/bw1;

    invoke-virtual {v8}, Llyiahf/vczjk/bw1;->OooO0oo()I

    move-result v8

    and-int/lit8 v11, v8, 0x1

    if-eqz v11, :cond_4

    goto :goto_3

    :cond_4
    move v10, v7

    :goto_3
    iget-object v11, v1, Llyiahf/vczjk/x01;->OooOo0:Llyiahf/vczjk/rr0;

    if-nez v11, :cond_5

    move v11, v7

    goto :goto_4

    :cond_5
    invoke-virtual {v11}, Llyiahf/vczjk/rr0;->OooO0oo()V

    iget-object v11, v11, Llyiahf/vczjk/rr0;->OooOOOo:Ljava/lang/Object;

    check-cast v11, Llyiahf/vczjk/tr0;

    iget-object v11, v11, Llyiahf/vczjk/x13;->OooOOO:[Ljava/lang/Object;

    array-length v11, v11

    :goto_4
    const/4 v12, 0x2

    if-eqz v2, :cond_9

    invoke-virtual {v1}, Llyiahf/vczjk/y86;->OooO0oO()Ljava/lang/String;

    move-result-object v13

    invoke-virtual {v5}, Llyiahf/vczjk/vt1;->OooO00o()Ljava/lang/String;

    move-result-object v14

    new-instance v15, Ljava/lang/StringBuilder;

    invoke-direct {v15}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v15, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v13, " "

    invoke-virtual {v15, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v15, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v15}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v13

    invoke-virtual {v0, v7, v13}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    invoke-static {v4}, Llyiahf/vczjk/u34;->Oooooo0(I)Ljava/lang/String;

    move-result-object v13

    const-string v14, "  registers_size: "

    invoke-virtual {v14, v13}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v13

    invoke-virtual {v0, v12, v13}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    invoke-static {v6}, Llyiahf/vczjk/u34;->Oooooo0(I)Ljava/lang/String;

    move-result-object v13

    const-string v14, "  ins_size:       "

    invoke-virtual {v14, v13}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v13

    invoke-virtual {v0, v12, v13}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    invoke-static {v9}, Llyiahf/vczjk/u34;->Oooooo0(I)Ljava/lang/String;

    move-result-object v13

    const-string v14, "  outs_size:      "

    invoke-virtual {v14, v13}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v13

    invoke-virtual {v0, v12, v13}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    invoke-static {v11}, Llyiahf/vczjk/u34;->Oooooo0(I)Ljava/lang/String;

    move-result-object v13

    const-string v14, "  tries_size:     "

    invoke-virtual {v14, v13}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v13

    invoke-virtual {v0, v12, v13}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    invoke-static {v7}, Llyiahf/vczjk/u34;->Oooooo(I)Ljava/lang/String;

    move-result-object v13

    const-string v14, "  debug_off:      "

    invoke-virtual {v14, v13}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v13

    const/4 v14, 0x4

    invoke-virtual {v0, v14, v13}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    invoke-static {v8}, Llyiahf/vczjk/u34;->Oooooo(I)Ljava/lang/String;

    move-result-object v13

    const-string v15, "  insns_size:     "

    invoke-virtual {v15, v13}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v13

    invoke-virtual {v0, v14, v13}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    iget-object v13, v1, Llyiahf/vczjk/x01;->OooOo00:Llyiahf/vczjk/d59;

    iget-object v14, v13, Llyiahf/vczjk/x13;->OooOOO:[Ljava/lang/Object;

    array-length v15, v14

    if-eqz v15, :cond_9

    array-length v14, v14

    if-nez v14, :cond_6

    const-string v13, "<empty>"

    goto :goto_6

    :cond_6
    new-instance v15, Ljava/lang/StringBuilder;

    const/16 v12, 0x64

    invoke-direct {v15, v12}, Ljava/lang/StringBuilder;-><init>(I)V

    move v12, v7

    :goto_5
    if-ge v12, v14, :cond_8

    if-eqz v12, :cond_7

    const-string v7, ", "

    invoke-virtual {v15, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    :cond_7
    invoke-virtual {v13, v12}, Llyiahf/vczjk/x13;->OooO0o0(I)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/p1a;

    invoke-virtual {v7}, Llyiahf/vczjk/p1a;->OooO00o()Ljava/lang/String;

    move-result-object v7

    invoke-virtual {v15, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    add-int/lit8 v12, v12, 0x1

    const/4 v7, 0x0

    goto :goto_5

    :cond_8
    invoke-virtual {v15}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v13

    :goto_6
    new-instance v7, Ljava/lang/StringBuilder;

    const-string v12, "  throws "

    invoke-direct {v7, v12}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v7, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v7

    const/4 v12, 0x0

    invoke-virtual {v0, v12, v7}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    goto :goto_7

    :cond_9
    move v12, v7

    :goto_7
    invoke-virtual {v0, v4}, Llyiahf/vczjk/ol0;->OooOO0O(I)V

    invoke-virtual {v0, v6}, Llyiahf/vczjk/ol0;->OooOO0O(I)V

    invoke-virtual {v0, v9}, Llyiahf/vczjk/ol0;->OooOO0O(I)V

    invoke-virtual {v0, v11}, Llyiahf/vczjk/ol0;->OooOO0O(I)V

    invoke-virtual {v0, v12}, Llyiahf/vczjk/ol0;->OooOO0(I)V

    invoke-virtual {v0, v8}, Llyiahf/vczjk/ol0;->OooOO0(I)V

    invoke-virtual {v3}, Llyiahf/vczjk/ld9;->Oooo()V

    iget-object v3, v3, Llyiahf/vczjk/ld9;->OooOOo0:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/bw1;

    :try_start_0
    invoke-virtual {v3, v0}, Llyiahf/vczjk/bw1;->OooO(Llyiahf/vczjk/ol0;)V
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    iget-object v3, v1, Llyiahf/vczjk/x01;->OooOo0:Llyiahf/vczjk/rr0;

    if-eqz v3, :cond_14

    if-eqz v10, :cond_b

    if-eqz v2, :cond_a

    const-string v2, "  padding: 0"

    const/4 v3, 0x2

    invoke-virtual {v0, v3, v2}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    :cond_a
    const/4 v12, 0x0

    invoke-virtual {v0, v12}, Llyiahf/vczjk/ol0;->OooOO0O(I)V

    :cond_b
    iget-object v2, v1, Llyiahf/vczjk/x01;->OooOo0:Llyiahf/vczjk/rr0;

    invoke-virtual {v2}, Llyiahf/vczjk/rr0;->OooO0oo()V

    invoke-virtual {v0}, Llyiahf/vczjk/ol0;->OooO0Oo()Z

    move-result v3

    const-string v4, ".."

    if-eqz v3, :cond_11

    invoke-virtual {v2}, Llyiahf/vczjk/rr0;->OooO0oo()V

    iget-object v3, v2, Llyiahf/vczjk/rr0;->OooOOOo:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/tr0;

    iget-object v3, v3, Llyiahf/vczjk/x13;->OooOOO:[Ljava/lang/Object;

    array-length v3, v3

    const-string v5, "  tries:"

    const/4 v12, 0x0

    invoke-virtual {v0, v12, v5}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    const/4 v12, 0x0

    :goto_8
    const-string v5, "    "

    if-ge v12, v3, :cond_e

    iget-object v6, v2, Llyiahf/vczjk/rr0;->OooOOOo:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/tr0;

    invoke-virtual {v6, v12}, Llyiahf/vczjk/x13;->OooO0o0(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/sr0;

    iget v7, v6, Llyiahf/vczjk/sr0;->OooOOO0:I

    int-to-char v8, v7

    if-ne v7, v8, :cond_c

    invoke-static {v7}, Llyiahf/vczjk/u34;->Oooooo0(I)Ljava/lang/String;

    move-result-object v7

    goto :goto_9

    :cond_c
    invoke-static {v7}, Llyiahf/vczjk/u34;->Oooooo(I)Ljava/lang/String;

    move-result-object v7

    :goto_9
    iget v8, v6, Llyiahf/vczjk/sr0;->OooOOO:I

    int-to-char v9, v8

    if-ne v8, v9, :cond_d

    invoke-static {v8}, Llyiahf/vczjk/u34;->Oooooo0(I)Ljava/lang/String;

    move-result-object v8

    goto :goto_a

    :cond_d
    invoke-static {v8}, Llyiahf/vczjk/u34;->Oooooo(I)Ljava/lang/String;

    move-result-object v8

    :goto_a
    const-string v9, "    try "

    invoke-static {v9, v7, v4, v8}, Llyiahf/vczjk/ii5;->OooO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v7

    iget-object v6, v6, Llyiahf/vczjk/sr0;->OooOOOO:Llyiahf/vczjk/qr0;

    const-string v8, ""

    invoke-virtual {v6, v5, v8}, Llyiahf/vczjk/qr0;->OooO(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v5

    const/4 v6, 0x6

    invoke-virtual {v0, v6, v7}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    const/4 v6, 0x2

    invoke-virtual {v0, v6, v5}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    add-int/lit8 v12, v12, 0x1

    goto :goto_8

    :cond_e
    const-string v3, "  handlers:"

    const/4 v12, 0x0

    invoke-virtual {v0, v12, v3}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    iget v3, v2, Llyiahf/vczjk/rr0;->OooOOO:I

    iget-object v6, v2, Llyiahf/vczjk/rr0;->OooOOo:Ljava/lang/Object;

    check-cast v6, Ljava/util/TreeMap;

    invoke-virtual {v6}, Ljava/util/TreeMap;->size()I

    move-result v6

    invoke-static {v6}, Llyiahf/vczjk/u34;->Oooooo0(I)Ljava/lang/String;

    move-result-object v6

    const-string v7, "    size: "

    invoke-virtual {v7, v6}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v6

    invoke-virtual {v0, v3, v6}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    iget-object v3, v2, Llyiahf/vczjk/rr0;->OooOOo:Ljava/lang/Object;

    check-cast v3, Ljava/util/TreeMap;

    invoke-virtual {v3}, Ljava/util/TreeMap;->entrySet()Ljava/util/Set;

    move-result-object v3

    invoke-interface {v3}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v3

    const/4 v6, 0x0

    move v7, v12

    :goto_b
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v8

    const-string v9, ": "

    if-eqz v8, :cond_10

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Ljava/util/Map$Entry;

    invoke-interface {v8}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/qr0;

    invoke-interface {v8}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Ljava/lang/Integer;

    invoke-virtual {v8}, Ljava/lang/Integer;->intValue()I

    move-result v8

    if-eqz v6, :cond_f

    sub-int v11, v8, v7

    invoke-static {v7}, Llyiahf/vczjk/u34;->Oooooo0(I)Ljava/lang/String;

    move-result-object v7

    invoke-virtual {v7, v9}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v7

    invoke-virtual {v6, v5, v7}, Llyiahf/vczjk/qr0;->OooO(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v6

    invoke-virtual {v0, v11, v6}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    :cond_f
    move v7, v8

    move-object v6, v10

    goto :goto_b

    :cond_10
    iget-object v3, v2, Llyiahf/vczjk/rr0;->OooOOo0:Ljava/io/Serializable;

    check-cast v3, [B

    array-length v3, v3

    sub-int/2addr v3, v7

    invoke-static {v7}, Llyiahf/vczjk/u34;->Oooooo0(I)Ljava/lang/String;

    move-result-object v7

    invoke-virtual {v7, v9}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v7

    invoke-virtual {v6, v5, v7}, Llyiahf/vczjk/qr0;->OooO(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v0, v3, v5}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    goto :goto_c

    :cond_11
    const/4 v12, 0x0

    :goto_c
    iget-object v3, v2, Llyiahf/vczjk/rr0;->OooOOOo:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/tr0;

    iget-object v3, v3, Llyiahf/vczjk/x13;->OooOOO:[Ljava/lang/Object;

    array-length v3, v3

    move v7, v12

    :goto_d
    if-ge v7, v3, :cond_13

    iget-object v5, v2, Llyiahf/vczjk/rr0;->OooOOOo:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/tr0;

    invoke-virtual {v5, v7}, Llyiahf/vczjk/x13;->OooO0o0(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/sr0;

    iget v6, v5, Llyiahf/vczjk/sr0;->OooOOO:I

    iget v8, v5, Llyiahf/vczjk/sr0;->OooOOO0:I

    sub-int v9, v6, v8

    const/high16 v10, 0x10000

    if-ge v9, v10, :cond_12

    invoke-virtual {v0, v8}, Llyiahf/vczjk/ol0;->OooOO0(I)V

    invoke-virtual {v0, v9}, Llyiahf/vczjk/ol0;->OooOO0O(I)V

    iget-object v6, v2, Llyiahf/vczjk/rr0;->OooOOo:Ljava/lang/Object;

    check-cast v6, Ljava/util/TreeMap;

    iget-object v5, v5, Llyiahf/vczjk/sr0;->OooOOOO:Llyiahf/vczjk/qr0;

    invoke-virtual {v6, v5}, Ljava/util/TreeMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/lang/Integer;

    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    move-result v5

    invoke-virtual {v0, v5}, Llyiahf/vczjk/ol0;->OooOO0O(I)V

    add-int/lit8 v7, v7, 0x1

    goto :goto_d

    :cond_12
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-static {v8}, Llyiahf/vczjk/u34;->Oooooo(I)Ljava/lang/String;

    move-result-object v2

    invoke-static {v6}, Llyiahf/vczjk/u34;->Oooooo(I)Ljava/lang/String;

    move-result-object v3

    const-string v5, "bogus exception range: "

    invoke-static {v5, v2, v4, v3}, Llyiahf/vczjk/ii5;->OooO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    invoke-direct {v0, v2}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_13
    iget-object v2, v2, Llyiahf/vczjk/rr0;->OooOOo0:Ljava/io/Serializable;

    check-cast v2, [B

    invoke-virtual {v0, v2}, Llyiahf/vczjk/ol0;->OooO0oo([B)V

    :cond_14
    return-void

    :catch_0
    move-exception v0

    invoke-virtual {v5}, Llyiahf/vczjk/vt1;->OooO00o()Ljava/lang/String;

    move-result-object v2

    new-instance v3, Ljava/lang/StringBuilder;

    const-string v4, "...while writing instructions for "

    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-static {v2, v0}, Llyiahf/vczjk/vr2;->OooO0O0(Ljava/lang/String;Ljava/lang/Exception;)Llyiahf/vczjk/vr2;

    move-result-object v0

    throw v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/x01;->OooOOo0:Llyiahf/vczjk/wt1;

    invoke-virtual {v0}, Llyiahf/vczjk/vt1;->OooO00o()Ljava/lang/String;

    move-result-object v0

    const-string v1, "CodeItem{"

    const-string v2, "}"

    invoke-static {v1, v0, v2}, Llyiahf/vczjk/u81;->OooOOO0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
