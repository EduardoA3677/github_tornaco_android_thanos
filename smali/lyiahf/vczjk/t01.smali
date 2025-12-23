.class public final Llyiahf/vczjk/t01;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public OooO:Ljava/lang/Object;

.field public OooO00o:Z

.field public final OooO0O0:Ljava/lang/Object;

.field public OooO0OO:Ljava/io/Serializable;

.field public final OooO0Oo:Ljava/lang/Object;

.field public OooO0o:Ljava/lang/Object;

.field public OooO0o0:Ljava/lang/Object;

.field public OooO0oO:Ljava/lang/Object;

.field public OooO0oo:Ljava/lang/Object;

.field public OooOO0:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bj0;Ljava/lang/Object;Z)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/t01;->OooO0Oo:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/t01;->OooO0O0:Ljava/lang/Object;

    iput-boolean p3, p0, Llyiahf/vczjk/t01;->OooO00o:Z

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/w92;)V
    .locals 5

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/t01;->OooO0OO:Ljava/io/Serializable;

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/t01;->OooO0Oo:Ljava/lang/Object;

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    iput-object v1, p0, Llyiahf/vczjk/t01;->OooO0o0:Ljava/lang/Object;

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    iput-object v1, p0, Llyiahf/vczjk/t01;->OooO0o:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/ay8;->OooO00o:Llyiahf/vczjk/ay8;

    iput-object v1, p0, Llyiahf/vczjk/t01;->OooO:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/d59;->OooOOOO:Llyiahf/vczjk/d59;

    iput-object v1, p0, Llyiahf/vczjk/t01;->OooOO0:Ljava/lang/Object;

    iget-object v1, p1, Llyiahf/vczjk/w92;->OooO00o:Llyiahf/vczjk/zi5;

    iput-object v1, p0, Llyiahf/vczjk/t01;->OooO0O0:Ljava/lang/Object;

    iget p1, p1, Llyiahf/vczjk/w92;->OooO0O0:I

    and-int/lit8 p1, p1, 0x8

    if-eqz p1, :cond_0

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/t01;->OooO0oO:Ljava/lang/Object;

    goto :goto_0

    :cond_0
    new-instance p1, Llyiahf/vczjk/m35;

    iget-object v2, v1, Llyiahf/vczjk/zi5;->OooO00o:Llyiahf/vczjk/b4a;

    invoke-direct {p1, p0, v2}, Llyiahf/vczjk/m35;-><init>(Llyiahf/vczjk/t01;Llyiahf/vczjk/b4a;)V

    iput-object p1, p0, Llyiahf/vczjk/t01;->OooO0oO:Ljava/lang/Object;

    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :goto_0
    iget-object p1, v1, Llyiahf/vczjk/zi5;->OooO0Oo:Llyiahf/vczjk/o4a;

    iget-object p1, p1, Llyiahf/vczjk/o4a;->OooO00o:[Llyiahf/vczjk/b4a;

    array-length v0, p1

    const/4 v1, 0x0

    :goto_1
    if-ge v1, v0, :cond_1

    aget-object v2, p1, v1

    iget-object v3, p0, Llyiahf/vczjk/t01;->OooO0Oo:Ljava/lang/Object;

    check-cast v3, Ljava/util/ArrayList;

    new-instance v4, Llyiahf/vczjk/m35;

    invoke-direct {v4, p0, v2}, Llyiahf/vczjk/m35;-><init>(Llyiahf/vczjk/t01;Llyiahf/vczjk/b4a;)V

    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v1, v1, 0x1

    goto :goto_1

    :cond_1
    new-instance p1, Llyiahf/vczjk/nm4;

    invoke-direct {p1}, Llyiahf/vczjk/nm4;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/t01;->OooO0oo:Ljava/lang/Object;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/t01;->OooO0OO(Llyiahf/vczjk/nm4;)V

    iget-object p1, p0, Llyiahf/vczjk/t01;->OooO0oo:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/nm4;

    const/4 v0, 0x1

    iput-boolean v0, p1, Llyiahf/vczjk/nm4;->OooO0OO:Z

    return-void
.end method

.method public static OooO00o(Ljava/lang/Object;)V
    .locals 1

    if-nez p0, :cond_0

    return-void

    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string v0, "Trying to call same allocXxx() method second time"

    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static OooO0o(Llyiahf/vczjk/m35;Llyiahf/vczjk/b4a;)V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/m35;->OooO00o:Llyiahf/vczjk/b4a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/b4a;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    return-void

    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-static {p1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    iget-object p0, p0, Llyiahf/vczjk/m35;->OooO00o:Llyiahf/vczjk/b4a;

    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p0

    const-string v1, "requested "

    const-string v2, " but was "

    invoke-static {v1, p1, v2, p0}, Llyiahf/vczjk/ii5;->OooO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method


# virtual methods
.method public varargs OooO(Llyiahf/vczjk/dv7;Llyiahf/vczjk/zi5;Llyiahf/vczjk/m35;Llyiahf/vczjk/m35;[Llyiahf/vczjk/m35;)V
    .locals 7

    new-instance v0, Llyiahf/vczjk/lr9;

    const/4 v6, 0x0

    if-eqz p4, :cond_0

    const/4 v1, 0x1

    goto :goto_0

    :cond_0
    move v1, v6

    :goto_0
    new-instance v3, Llyiahf/vczjk/tn7;

    array-length v2, p5

    add-int/2addr v2, v1

    invoke-direct {v3, v2}, Llyiahf/vczjk/x13;-><init>(I)V

    if-eqz p4, :cond_1

    invoke-virtual {p4}, Llyiahf/vczjk/m35;->OooO00o()Llyiahf/vczjk/sn7;

    move-result-object p4

    invoke-virtual {v3, v6, p4}, Llyiahf/vczjk/x13;->OooO0o(ILjava/lang/Object;)V

    :cond_1
    move p4, v6

    :goto_1
    array-length v2, p5

    if-ge p4, v2, :cond_2

    add-int v2, p4, v1

    aget-object v4, p5, p4

    invoke-virtual {v4}, Llyiahf/vczjk/m35;->OooO00o()Llyiahf/vczjk/sn7;

    move-result-object v4

    invoke-virtual {v3, v2, v4}, Llyiahf/vczjk/x13;->OooO0o(ILjava/lang/Object;)V

    add-int/lit8 p4, p4, 0x1

    goto :goto_1

    :cond_2
    iget-object p4, p0, Llyiahf/vczjk/t01;->OooOO0:Ljava/lang/Object;

    move-object v4, p4

    check-cast v4, Llyiahf/vczjk/d59;

    iget-object v5, p2, Llyiahf/vczjk/zi5;->OooO0o0:Llyiahf/vczjk/wt1;

    iget-object p2, p0, Llyiahf/vczjk/t01;->OooO:Ljava/lang/Object;

    move-object v2, p2

    check-cast v2, Llyiahf/vczjk/ay8;

    move-object v1, p1

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/lr9;-><init>(Llyiahf/vczjk/dv7;Llyiahf/vczjk/ay8;Llyiahf/vczjk/tn7;Llyiahf/vczjk/n4a;Llyiahf/vczjk/hj1;)V

    const/4 p1, 0x0

    invoke-virtual {p0, v0, p1}, Llyiahf/vczjk/t01;->OooO0O0(Llyiahf/vczjk/g14;Llyiahf/vczjk/nm4;)V

    if-eqz p3, :cond_3

    invoke-virtual {p0, p3, v6}, Llyiahf/vczjk/t01;->OooOO0o(Llyiahf/vczjk/m35;Z)V

    :cond_3
    return-void
.end method

.method public OooO0O0(Llyiahf/vczjk/g14;Llyiahf/vczjk/nm4;)V
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/t01;->OooO0oo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/nm4;

    if-eqz v0, :cond_a

    iget-boolean v1, v0, Llyiahf/vczjk/nm4;->OooO0OO:Z

    if-eqz v1, :cond_a

    iget-object v0, v0, Llyiahf/vczjk/nm4;->OooO00o:Ljava/util/ArrayList;

    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    iget-object p1, p1, Llyiahf/vczjk/g14;->OooOOO0:Llyiahf/vczjk/dv7;

    iget p1, p1, Llyiahf/vczjk/dv7;->OooO0o0:I

    const/4 v0, 0x1

    const-string v1, "unexpected branch: "

    if-eq p1, v0, :cond_8

    const/4 v2, 0x2

    const/4 v3, 0x0

    if-eq p1, v2, :cond_6

    const/4 v2, 0x3

    const-string v4, "branch == null"

    if-eq p1, v2, :cond_4

    const/4 v2, 0x4

    if-eq p1, v2, :cond_2

    const/4 v2, 0x6

    if-ne p1, v2, :cond_1

    if-nez p2, :cond_0

    new-instance p1, Ljava/util/ArrayList;

    iget-object p2, p0, Llyiahf/vczjk/t01;->OooO0o:Ljava/lang/Object;

    check-cast p2, Ljava/util/ArrayList;

    invoke-direct {p1, p2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    new-instance p2, Llyiahf/vczjk/nm4;

    invoke-direct {p2}, Llyiahf/vczjk/nm4;-><init>()V

    invoke-virtual {p0, p2}, Llyiahf/vczjk/t01;->OooO0OO(Llyiahf/vczjk/nm4;)V

    iget-object v1, p0, Llyiahf/vczjk/t01;->OooO0oo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/nm4;

    iput-object p2, v1, Llyiahf/vczjk/nm4;->OooO0o0:Llyiahf/vczjk/nm4;

    iput-object v3, v1, Llyiahf/vczjk/nm4;->OooO0o:Llyiahf/vczjk/nm4;

    iput-object p1, v1, Llyiahf/vczjk/nm4;->OooO0Oo:Ljava/util/List;

    iput-object p2, p0, Llyiahf/vczjk/t01;->OooO0oo:Ljava/lang/Object;

    iput-boolean v0, p2, Llyiahf/vczjk/nm4;->OooO0OO:Z

    return-void

    :cond_0
    new-instance p1, Ljava/lang/IllegalArgumentException;

    invoke-static {p2}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p2

    invoke-virtual {v1, p2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    invoke-direct {p1, p2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    new-instance p1, Ljava/lang/IllegalArgumentException;

    invoke-direct {p1}, Ljava/lang/IllegalArgumentException;-><init>()V

    throw p1

    :cond_2
    if-eqz p2, :cond_3

    sget-object p1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    new-instance v1, Llyiahf/vczjk/nm4;

    invoke-direct {v1}, Llyiahf/vczjk/nm4;-><init>()V

    invoke-virtual {p0, v1}, Llyiahf/vczjk/t01;->OooO0OO(Llyiahf/vczjk/nm4;)V

    iget-object v2, p0, Llyiahf/vczjk/t01;->OooO0oo:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/nm4;

    iput-object v1, v2, Llyiahf/vczjk/nm4;->OooO0o0:Llyiahf/vczjk/nm4;

    iput-object p2, v2, Llyiahf/vczjk/nm4;->OooO0o:Llyiahf/vczjk/nm4;

    iput-object p1, v2, Llyiahf/vczjk/nm4;->OooO0Oo:Ljava/util/List;

    iput-object v1, p0, Llyiahf/vczjk/t01;->OooO0oo:Ljava/lang/Object;

    iput-boolean v0, v1, Llyiahf/vczjk/nm4;->OooO0OO:Z

    return-void

    :cond_3
    new-instance p1, Ljava/lang/IllegalArgumentException;

    invoke-direct {p1, v4}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_4
    if-eqz p2, :cond_5

    iget-object p1, p0, Llyiahf/vczjk/t01;->OooO0oo:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/nm4;

    iput-object p2, p1, Llyiahf/vczjk/nm4;->OooO0o0:Llyiahf/vczjk/nm4;

    iput-object v3, p0, Llyiahf/vczjk/t01;->OooO0oo:Ljava/lang/Object;

    return-void

    :cond_5
    new-instance p1, Ljava/lang/IllegalArgumentException;

    invoke-direct {p1, v4}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_6
    if-nez p2, :cond_7

    iput-object v3, p0, Llyiahf/vczjk/t01;->OooO0oo:Ljava/lang/Object;

    return-void

    :cond_7
    new-instance p1, Ljava/lang/IllegalArgumentException;

    invoke-static {p2}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p2

    invoke-virtual {v1, p2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    invoke-direct {p1, p2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_8
    if-nez p2, :cond_9

    return-void

    :cond_9
    new-instance p1, Ljava/lang/IllegalArgumentException;

    invoke-static {p2}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p2

    invoke-virtual {v1, p2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    invoke-direct {p1, p2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_a
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "no current label"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public OooO0OO(Llyiahf/vczjk/nm4;)V
    .locals 1

    iget-object v0, p1, Llyiahf/vczjk/nm4;->OooO0O0:Llyiahf/vczjk/t01;

    if-ne v0, p0, :cond_0

    return-void

    :cond_0
    if-nez v0, :cond_1

    iput-object p0, p1, Llyiahf/vczjk/nm4;->OooO0O0:Llyiahf/vczjk/t01;

    iget-object v0, p0, Llyiahf/vczjk/t01;->OooO0OO:Ljava/io/Serializable;

    check-cast v0, Ljava/util/ArrayList;

    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-void

    :cond_1
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Cannot adopt label; it belongs to another Code"

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public OooO0Oo()[B
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/t01;->OooO0oO:Ljava/lang/Object;

    check-cast v0, [B

    invoke-static {v0}, Llyiahf/vczjk/t01;->OooO00o(Ljava/lang/Object;)V

    iget-object v0, p0, Llyiahf/vczjk/t01;->OooO0Oo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/bj0;

    const/4 v1, 0x3

    invoke-virtual {v0, v1}, Llyiahf/vczjk/bj0;->OooO00o(I)[B

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/t01;->OooO0oO:Ljava/lang/Object;

    return-object v0
.end method

.method public OooO0o0(Llyiahf/vczjk/m35;Llyiahf/vczjk/m35;)V
    .locals 11

    iget-object v0, p2, Llyiahf/vczjk/m35;->OooO00o:Llyiahf/vczjk/b4a;

    iget-object v0, v0, Llyiahf/vczjk/b4a;->OooO0O0:Llyiahf/vczjk/p1a;

    iget v1, v0, Llyiahf/vczjk/p1a;->OooOOO:I

    const/16 v2, 0x9

    const/4 v3, 0x1

    if-ne v1, v2, :cond_0

    move v2, v3

    goto :goto_0

    :cond_0
    const/4 v2, 0x0

    :goto_0
    const/4 v4, 0x0

    if-eqz v2, :cond_1

    new-instance v5, Llyiahf/vczjk/lr9;

    sget-object v6, Llyiahf/vczjk/kv7;->o000Oo0O:Llyiahf/vczjk/dv7;

    invoke-virtual {p2}, Llyiahf/vczjk/m35;->OooO00o()Llyiahf/vczjk/sn7;

    move-result-object p2

    invoke-static {p2}, Llyiahf/vczjk/tn7;->OooO0oo(Llyiahf/vczjk/sn7;)Llyiahf/vczjk/tn7;

    move-result-object v8

    iget-object p2, p1, Llyiahf/vczjk/m35;->OooO00o:Llyiahf/vczjk/b4a;

    iget-object v10, p2, Llyiahf/vczjk/b4a;->OooO0OO:Llyiahf/vczjk/au1;

    iget-object p2, p0, Llyiahf/vczjk/t01;->OooO:Ljava/lang/Object;

    move-object v7, p2

    check-cast v7, Llyiahf/vczjk/ay8;

    iget-object p2, p0, Llyiahf/vczjk/t01;->OooOO0:Ljava/lang/Object;

    move-object v9, p2

    check-cast v9, Llyiahf/vczjk/d59;

    invoke-direct/range {v5 .. v10}, Llyiahf/vczjk/lr9;-><init>(Llyiahf/vczjk/dv7;Llyiahf/vczjk/ay8;Llyiahf/vczjk/tn7;Llyiahf/vczjk/n4a;Llyiahf/vczjk/hj1;)V

    invoke-virtual {p0, v5, v4}, Llyiahf/vczjk/t01;->OooO0O0(Llyiahf/vczjk/g14;Llyiahf/vczjk/nm4;)V

    invoke-virtual {p0, p1, v3}, Llyiahf/vczjk/t01;->OooOO0o(Llyiahf/vczjk/m35;Z)V

    return-void

    :cond_1
    new-instance v2, Llyiahf/vczjk/ww6;

    iget-object v3, p1, Llyiahf/vczjk/m35;->OooO00o:Llyiahf/vczjk/b4a;

    iget-object v3, v3, Llyiahf/vczjk/b4a;->OooO0O0:Llyiahf/vczjk/p1a;

    const/4 v5, 0x6

    if-ne v1, v5, :cond_5

    iget v1, v3, Llyiahf/vczjk/p1a;->OooOOO:I

    const/4 v6, 0x2

    if-eq v1, v6, :cond_4

    const/4 v6, 0x3

    if-eq v1, v6, :cond_3

    const/16 v6, 0x8

    if-eq v1, v6, :cond_2

    goto :goto_1

    :cond_2
    sget-object v0, Llyiahf/vczjk/kv7;->o0000OOO:Llyiahf/vczjk/dv7;

    goto/16 :goto_5

    :cond_3
    sget-object v0, Llyiahf/vczjk/kv7;->o0000OO:Llyiahf/vczjk/dv7;

    goto/16 :goto_5

    :cond_4
    sget-object v0, Llyiahf/vczjk/kv7;->o0000OO0:Llyiahf/vczjk/dv7;

    goto/16 :goto_5

    :cond_5
    :goto_1
    sget-object v1, Llyiahf/vczjk/kv7;->OooO00o:Llyiahf/vczjk/dv7;

    invoke-virtual {v3}, Llyiahf/vczjk/p1a;->OooO0O0()I

    move-result v1

    invoke-virtual {v0}, Llyiahf/vczjk/p1a;->OooO0O0()I

    move-result v6

    const/4 v7, 0x7

    const/4 v8, 0x5

    const/4 v9, 0x4

    if-eq v6, v9, :cond_11

    if-eq v6, v8, :cond_d

    if-eq v6, v5, :cond_6

    if-ne v6, v7, :cond_12

    goto :goto_2

    :cond_6
    if-eq v1, v9, :cond_c

    if-eq v1, v8, :cond_b

    if-eq v1, v7, :cond_a

    :goto_2
    if-eq v1, v9, :cond_9

    if-eq v1, v8, :cond_8

    if-eq v1, v5, :cond_7

    goto :goto_3

    :cond_7
    sget-object v0, Llyiahf/vczjk/kv7;->o00000o0:Llyiahf/vczjk/dv7;

    goto :goto_5

    :cond_8
    sget-object v0, Llyiahf/vczjk/kv7;->o0000oO:Llyiahf/vczjk/dv7;

    goto :goto_5

    :cond_9
    sget-object v0, Llyiahf/vczjk/kv7;->o000OO:Llyiahf/vczjk/dv7;

    goto :goto_5

    :cond_a
    sget-object v0, Llyiahf/vczjk/kv7;->o00000oo:Llyiahf/vczjk/dv7;

    goto :goto_5

    :cond_b
    sget-object v0, Llyiahf/vczjk/kv7;->o0000oo:Llyiahf/vczjk/dv7;

    goto :goto_5

    :cond_c
    sget-object v0, Llyiahf/vczjk/kv7;->o0000O0O:Llyiahf/vczjk/dv7;

    goto :goto_5

    :cond_d
    :goto_3
    if-eq v1, v9, :cond_10

    if-eq v1, v5, :cond_f

    if-eq v1, v7, :cond_e

    goto :goto_4

    :cond_e
    sget-object v0, Llyiahf/vczjk/kv7;->o0000:Llyiahf/vczjk/dv7;

    goto :goto_5

    :cond_f
    sget-object v0, Llyiahf/vczjk/kv7;->o0000Ooo:Llyiahf/vczjk/dv7;

    goto :goto_5

    :cond_10
    sget-object v0, Llyiahf/vczjk/kv7;->o0000O:Llyiahf/vczjk/dv7;

    goto :goto_5

    :cond_11
    :goto_4
    if-eq v1, v8, :cond_14

    if-eq v1, v5, :cond_13

    if-ne v1, v7, :cond_12

    sget-object v0, Llyiahf/vczjk/kv7;->o0000O00:Llyiahf/vczjk/dv7;

    goto :goto_5

    :cond_12
    invoke-static {v3, v0}, Llyiahf/vczjk/d59;->OooO(Llyiahf/vczjk/p1a;Llyiahf/vczjk/p1a;)Llyiahf/vczjk/d59;

    move-result-object p1

    new-instance p2, Ljava/lang/IllegalArgumentException;

    invoke-static {p1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    const-string v0, "bad types: "

    invoke-virtual {v0, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p2

    :cond_13
    sget-object v0, Llyiahf/vczjk/kv7;->o00000oO:Llyiahf/vczjk/dv7;

    goto :goto_5

    :cond_14
    sget-object v0, Llyiahf/vczjk/kv7;->o0000O0:Llyiahf/vczjk/dv7;

    :goto_5
    invoke-virtual {p1}, Llyiahf/vczjk/m35;->OooO00o()Llyiahf/vczjk/sn7;

    move-result-object p1

    invoke-virtual {p2}, Llyiahf/vczjk/m35;->OooO00o()Llyiahf/vczjk/sn7;

    move-result-object p2

    invoke-static {p2}, Llyiahf/vczjk/tn7;->OooO0oo(Llyiahf/vczjk/sn7;)Llyiahf/vczjk/tn7;

    move-result-object p2

    iget-object v1, p0, Llyiahf/vczjk/t01;->OooO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ay8;

    invoke-direct {v2, v0, v1, p1, p2}, Llyiahf/vczjk/ww6;-><init>(Llyiahf/vczjk/dv7;Llyiahf/vczjk/ay8;Llyiahf/vczjk/sn7;Llyiahf/vczjk/tn7;)V

    invoke-virtual {p0, v2, v4}, Llyiahf/vczjk/t01;->OooO0O0(Llyiahf/vczjk/g14;Llyiahf/vczjk/nm4;)V

    return-void
.end method

.method public OooO0oO(ILlyiahf/vczjk/b4a;)Llyiahf/vczjk/m35;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/t01;->OooO0oO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/m35;

    if-eqz v0, :cond_0

    add-int/lit8 p1, p1, 0x1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/t01;->OooO0Oo:Ljava/lang/Object;

    check-cast v0, Ljava/util/ArrayList;

    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/m35;

    invoke-static {p1, p2}, Llyiahf/vczjk/t01;->OooO0o(Llyiahf/vczjk/m35;Llyiahf/vczjk/b4a;)V

    return-object p1
.end method

.method public OooO0oo()V
    .locals 13

    iget-boolean v0, p0, Llyiahf/vczjk/t01;->OooO00o:Z

    if-nez v0, :cond_7

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/t01;->OooO00o:Z

    iget-object v0, p0, Llyiahf/vczjk/t01;->OooO0o0:Ljava/lang/Object;

    check-cast v0, Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    const/4 v1, 0x0

    move v2, v1

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/m35;

    iput v2, v3, Llyiahf/vczjk/m35;->OooO0OO:I

    iget-object v4, v3, Llyiahf/vczjk/m35;->OooO00o:Llyiahf/vczjk/b4a;

    iget-object v5, v4, Llyiahf/vczjk/b4a;->OooO0O0:Llyiahf/vczjk/p1a;

    invoke-static {v2, v5}, Llyiahf/vczjk/sn7;->OooO0Oo(ILlyiahf/vczjk/f3a;)Llyiahf/vczjk/sn7;

    move-result-object v5

    iput-object v5, v3, Llyiahf/vczjk/m35;->OooO0Oo:Llyiahf/vczjk/sn7;

    iget-object v3, v4, Llyiahf/vczjk/b4a;->OooO0O0:Llyiahf/vczjk/p1a;

    invoke-virtual {v3}, Llyiahf/vczjk/p1a;->OooO0Oo()I

    move-result v3

    add-int/2addr v2, v3

    goto :goto_0

    :cond_0
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iget-object v3, p0, Llyiahf/vczjk/t01;->OooO0Oo:Ljava/lang/Object;

    check-cast v3, Ljava/util/ArrayList;

    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v3

    move v4, v2

    :goto_1
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_6

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/m35;

    sub-int v6, v4, v2

    invoke-static {v6}, Llyiahf/vczjk/pt1;->OooO(I)Llyiahf/vczjk/pt1;

    move-result-object v12

    iput v4, v5, Llyiahf/vczjk/m35;->OooO0OO:I

    iget-object v6, v5, Llyiahf/vczjk/m35;->OooO00o:Llyiahf/vczjk/b4a;

    iget-object v7, v6, Llyiahf/vczjk/b4a;->OooO0O0:Llyiahf/vczjk/p1a;

    invoke-static {v4, v7}, Llyiahf/vczjk/sn7;->OooO0Oo(ILlyiahf/vczjk/f3a;)Llyiahf/vczjk/sn7;

    move-result-object v7

    iput-object v7, v5, Llyiahf/vczjk/m35;->OooO0Oo:Llyiahf/vczjk/sn7;

    iget-object v7, v6, Llyiahf/vczjk/b4a;->OooO0O0:Llyiahf/vczjk/p1a;

    invoke-virtual {v7}, Llyiahf/vczjk/p1a;->OooO0Oo()I

    move-result v7

    add-int/2addr v4, v7

    new-instance v7, Llyiahf/vczjk/vw6;

    iget-object v6, v6, Llyiahf/vczjk/b4a;->OooO0O0:Llyiahf/vczjk/p1a;

    sget-object v8, Llyiahf/vczjk/kv7;->OooO00o:Llyiahf/vczjk/dv7;

    invoke-virtual {v6}, Llyiahf/vczjk/p1a;->OooO0O0()I

    move-result v8

    const/4 v9, 0x4

    if-eq v8, v9, :cond_5

    const/4 v9, 0x5

    if-eq v8, v9, :cond_4

    const/4 v9, 0x6

    if-eq v8, v9, :cond_3

    const/4 v9, 0x7

    if-eq v8, v9, :cond_2

    const/16 v9, 0x9

    if-ne v8, v9, :cond_1

    sget-object v6, Llyiahf/vczjk/kv7;->OooOO0O:Llyiahf/vczjk/dv7;

    :goto_2
    move-object v8, v6

    goto :goto_3

    :cond_1
    invoke-static {v6}, Llyiahf/vczjk/kv7;->OooO00o(Llyiahf/vczjk/f3a;)V

    const/4 v0, 0x0

    throw v0

    :cond_2
    sget-object v6, Llyiahf/vczjk/kv7;->OooO0oo:Llyiahf/vczjk/dv7;

    goto :goto_2

    :cond_3
    sget-object v6, Llyiahf/vczjk/kv7;->OooO0oO:Llyiahf/vczjk/dv7;

    goto :goto_2

    :cond_4
    sget-object v6, Llyiahf/vczjk/kv7;->OooO:Llyiahf/vczjk/dv7;

    goto :goto_2

    :cond_5
    sget-object v6, Llyiahf/vczjk/kv7;->OooOO0:Llyiahf/vczjk/dv7;

    goto :goto_2

    :goto_3
    invoke-virtual {v5}, Llyiahf/vczjk/m35;->OooO00o()Llyiahf/vczjk/sn7;

    move-result-object v10

    sget-object v11, Llyiahf/vczjk/tn7;->OooOOOO:Llyiahf/vczjk/tn7;

    iget-object v5, p0, Llyiahf/vczjk/t01;->OooO:Ljava/lang/Object;

    move-object v9, v5

    check-cast v9, Llyiahf/vczjk/ay8;

    invoke-direct/range {v7 .. v12}, Llyiahf/vczjk/vw6;-><init>(Llyiahf/vczjk/dv7;Llyiahf/vczjk/ay8;Llyiahf/vczjk/sn7;Llyiahf/vczjk/tn7;Llyiahf/vczjk/t5a;)V

    invoke-virtual {v0, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_6
    iget-object v2, p0, Llyiahf/vczjk/t01;->OooO0OO:Ljava/io/Serializable;

    check-cast v2, Ljava/util/ArrayList;

    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/nm4;

    iget-object v2, v2, Llyiahf/vczjk/nm4;->OooO00o:Ljava/util/ArrayList;

    invoke-virtual {v2, v1, v0}, Ljava/util/ArrayList;->addAll(ILjava/util/Collection;)Z

    return-void

    :cond_7
    new-instance v0, Ljava/lang/AssertionError;

    invoke-direct {v0}, Ljava/lang/AssertionError;-><init>()V

    throw v0
.end method

.method public varargs OooOO0(Llyiahf/vczjk/zi5;Llyiahf/vczjk/m35;Llyiahf/vczjk/m35;[Llyiahf/vczjk/m35;)V
    .locals 9

    const/4 v0, 0x1

    invoke-virtual {p1, v0}, Llyiahf/vczjk/zi5;->OooO00o(Z)Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_2

    sget-object v1, Llyiahf/vczjk/he7;->OooOOo0:Ljava/util/concurrent/ConcurrentHashMap;

    invoke-virtual {v1, v0}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/he7;

    if-eqz v2, :cond_0

    goto :goto_0

    :cond_0
    invoke-static {v0}, Llyiahf/vczjk/he7;->OooO0O0(Ljava/lang/String;)Llyiahf/vczjk/he7;

    move-result-object v2

    iget-object v0, v2, Llyiahf/vczjk/he7;->OooOOO0:Ljava/lang/String;

    invoke-virtual {v1, v0, v2}, Ljava/util/concurrent/ConcurrentHashMap;->putIfAbsent(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/he7;

    if-eqz v0, :cond_1

    move-object v2, v0

    :cond_1
    :goto_0
    sget-object v0, Llyiahf/vczjk/kv7;->OooO00o:Llyiahf/vczjk/dv7;

    new-instance v4, Llyiahf/vczjk/dv7;

    invoke-virtual {v2}, Llyiahf/vczjk/he7;->OooO0OO()Llyiahf/vczjk/d59;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/d59;->OooOo0O:Llyiahf/vczjk/d59;

    const/16 v2, 0x33

    invoke-direct {v4, v2, v0, v1}, Llyiahf/vczjk/dv7;-><init>(ILlyiahf/vczjk/d59;Llyiahf/vczjk/d59;)V

    move-object v3, p0

    move-object v5, p1

    move-object v6, p2

    move-object v7, p3

    move-object v8, p4

    invoke-virtual/range {v3 .. v8}, Llyiahf/vczjk/t01;->OooO(Llyiahf/vczjk/dv7;Llyiahf/vczjk/zi5;Llyiahf/vczjk/m35;Llyiahf/vczjk/m35;[Llyiahf/vczjk/m35;)V

    return-void

    :cond_2
    sget-object p1, Llyiahf/vczjk/he7;->OooOOo0:Ljava/util/concurrent/ConcurrentHashMap;

    new-instance p1, Ljava/lang/NullPointerException;

    const-string p2, "descriptor == null"

    invoke-direct {p1, p2}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public OooOO0O(Llyiahf/vczjk/m35;Ljava/lang/Object;)V
    .locals 9

    const/4 v0, 0x0

    if-nez p2, :cond_0

    sget-object v1, Llyiahf/vczjk/kv7;->OooOOo0:Llyiahf/vczjk/dv7;

    :goto_0
    move-object v3, v1

    goto :goto_1

    :cond_0
    iget-object v1, p1, Llyiahf/vczjk/m35;->OooO00o:Llyiahf/vczjk/b4a;

    iget-object v1, v1, Llyiahf/vczjk/b4a;->OooO0O0:Llyiahf/vczjk/p1a;

    sget-object v2, Llyiahf/vczjk/kv7;->OooO00o:Llyiahf/vczjk/dv7;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v2, Llyiahf/vczjk/p1a;->OooOoOO:Llyiahf/vczjk/p1a;

    if-ne v1, v2, :cond_1

    sget-object v1, Llyiahf/vczjk/kv7;->OooOOo0:Llyiahf/vczjk/dv7;

    goto :goto_0

    :cond_1
    invoke-virtual {v1}, Llyiahf/vczjk/p1a;->OooO0O0()I

    move-result v2

    const/4 v3, 0x4

    if-eq v2, v3, :cond_6

    const/4 v3, 0x5

    if-eq v2, v3, :cond_5

    const/4 v3, 0x6

    if-eq v2, v3, :cond_4

    const/4 v3, 0x7

    if-eq v2, v3, :cond_3

    const/16 v3, 0x9

    if-ne v2, v3, :cond_2

    sget-object v1, Llyiahf/vczjk/kv7;->OooOOOo:Llyiahf/vczjk/dv7;

    goto :goto_0

    :cond_2
    invoke-static {v1}, Llyiahf/vczjk/kv7;->OooO00o(Llyiahf/vczjk/f3a;)V

    throw v0

    :cond_3
    sget-object v1, Llyiahf/vczjk/kv7;->OooOOO0:Llyiahf/vczjk/dv7;

    goto :goto_0

    :cond_4
    sget-object v1, Llyiahf/vczjk/kv7;->OooOO0o:Llyiahf/vczjk/dv7;

    goto :goto_0

    :cond_5
    sget-object v1, Llyiahf/vczjk/kv7;->OooOOO:Llyiahf/vczjk/dv7;

    goto :goto_0

    :cond_6
    sget-object v1, Llyiahf/vczjk/kv7;->OooOOOO:Llyiahf/vczjk/dv7;

    goto :goto_0

    :goto_1
    iget v1, v3, Llyiahf/vczjk/dv7;->OooO0o0:I

    const/4 v8, 0x1

    if-ne v1, v8, :cond_7

    new-instance v2, Llyiahf/vczjk/vw6;

    invoke-virtual {p1}, Llyiahf/vczjk/m35;->OooO00o()Llyiahf/vczjk/sn7;

    move-result-object v5

    sget-object v6, Llyiahf/vczjk/tn7;->OooOOOO:Llyiahf/vczjk/tn7;

    invoke-static {p2}, Llyiahf/vczjk/e16;->OooOo0O(Ljava/lang/Object;)Llyiahf/vczjk/t5a;

    move-result-object v7

    iget-object p1, p0, Llyiahf/vczjk/t01;->OooO:Ljava/lang/Object;

    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/ay8;

    invoke-direct/range {v2 .. v7}, Llyiahf/vczjk/vw6;-><init>(Llyiahf/vczjk/dv7;Llyiahf/vczjk/ay8;Llyiahf/vczjk/sn7;Llyiahf/vczjk/tn7;Llyiahf/vczjk/t5a;)V

    invoke-virtual {p0, v2, v0}, Llyiahf/vczjk/t01;->OooO0O0(Llyiahf/vczjk/g14;Llyiahf/vczjk/nm4;)V

    return-void

    :cond_7
    new-instance v2, Llyiahf/vczjk/lr9;

    sget-object v5, Llyiahf/vczjk/tn7;->OooOOOO:Llyiahf/vczjk/tn7;

    invoke-static {p2}, Llyiahf/vczjk/e16;->OooOo0O(Ljava/lang/Object;)Llyiahf/vczjk/t5a;

    move-result-object v7

    iget-object p2, p0, Llyiahf/vczjk/t01;->OooO:Ljava/lang/Object;

    move-object v4, p2

    check-cast v4, Llyiahf/vczjk/ay8;

    iget-object p2, p0, Llyiahf/vczjk/t01;->OooOO0:Ljava/lang/Object;

    move-object v6, p2

    check-cast v6, Llyiahf/vczjk/d59;

    invoke-direct/range {v2 .. v7}, Llyiahf/vczjk/lr9;-><init>(Llyiahf/vczjk/dv7;Llyiahf/vczjk/ay8;Llyiahf/vczjk/tn7;Llyiahf/vczjk/n4a;Llyiahf/vczjk/hj1;)V

    invoke-virtual {p0, v2, v0}, Llyiahf/vczjk/t01;->OooO0O0(Llyiahf/vczjk/g14;Llyiahf/vczjk/nm4;)V

    invoke-virtual {p0, p1, v8}, Llyiahf/vczjk/t01;->OooOO0o(Llyiahf/vczjk/m35;Z)V

    return-void
.end method

.method public OooOO0o(Llyiahf/vczjk/m35;Z)V
    .locals 4

    const/4 v0, 0x0

    if-eqz p2, :cond_0

    iget-object p2, p1, Llyiahf/vczjk/m35;->OooO00o:Llyiahf/vczjk/b4a;

    iget-object p2, p2, Llyiahf/vczjk/b4a;->OooO0O0:Llyiahf/vczjk/p1a;

    sget-object v1, Llyiahf/vczjk/kv7;->OooO00o:Llyiahf/vczjk/dv7;

    new-instance v1, Llyiahf/vczjk/dv7;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v2, Llyiahf/vczjk/d59;->OooOOOO:Llyiahf/vczjk/d59;

    const/16 v3, 0x38

    invoke-direct {v1, v3, p2, v2, v0}, Llyiahf/vczjk/dv7;-><init>(ILlyiahf/vczjk/p1a;Llyiahf/vczjk/n4a;Ljava/lang/String;)V

    goto :goto_0

    :cond_0
    iget-object p2, p1, Llyiahf/vczjk/m35;->OooO00o:Llyiahf/vczjk/b4a;

    iget-object p2, p2, Llyiahf/vczjk/b4a;->OooO0O0:Llyiahf/vczjk/p1a;

    sget-object v1, Llyiahf/vczjk/kv7;->OooO00o:Llyiahf/vczjk/dv7;

    new-instance v1, Llyiahf/vczjk/dv7;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v2, Llyiahf/vczjk/d59;->OooOOOO:Llyiahf/vczjk/d59;

    const/16 v3, 0x37

    invoke-direct {v1, v3, p2, v2, v0}, Llyiahf/vczjk/dv7;-><init>(ILlyiahf/vczjk/p1a;Llyiahf/vczjk/n4a;Ljava/lang/String;)V

    :goto_0
    new-instance p2, Llyiahf/vczjk/ww6;

    invoke-virtual {p1}, Llyiahf/vczjk/m35;->OooO00o()Llyiahf/vczjk/sn7;

    move-result-object p1

    sget-object v2, Llyiahf/vczjk/tn7;->OooOOOO:Llyiahf/vczjk/tn7;

    iget-object v3, p0, Llyiahf/vczjk/t01;->OooO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/ay8;

    invoke-direct {p2, v1, v3, p1, v2}, Llyiahf/vczjk/ww6;-><init>(Llyiahf/vczjk/dv7;Llyiahf/vczjk/ay8;Llyiahf/vczjk/sn7;Llyiahf/vczjk/tn7;)V

    invoke-virtual {p0, p2, v0}, Llyiahf/vczjk/t01;->OooO0O0(Llyiahf/vczjk/g14;Llyiahf/vczjk/nm4;)V

    return-void
.end method

.method public OooOOO([B)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/t01;->OooO0oO:Ljava/lang/Object;

    check-cast v0, [B

    if-eq p1, v0, :cond_1

    array-length v1, p1

    array-length v0, v0

    if-lt v1, v0, :cond_0

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Trying to release buffer smaller than original"

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    :goto_0
    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/t01;->OooO0oO:Ljava/lang/Object;

    iget-object v0, p0, Llyiahf/vczjk/t01;->OooO0Oo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/bj0;

    iget-object v0, v0, Llyiahf/vczjk/bj0;->OooO00o:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    const/4 v1, 0x3

    invoke-virtual {v0, v1, p1}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->set(ILjava/lang/Object;)V

    return-void
.end method

.method public OooOOO0(Llyiahf/vczjk/b4a;)Llyiahf/vczjk/m35;
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/t01;->OooO00o:Z

    if-nez v0, :cond_0

    new-instance v0, Llyiahf/vczjk/m35;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/m35;-><init>(Llyiahf/vczjk/t01;Llyiahf/vczjk/b4a;)V

    iget-object p1, p0, Llyiahf/vczjk/t01;->OooO0o0:Ljava/lang/Object;

    check-cast p1, Ljava/util/ArrayList;

    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-object v0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "Cannot allocate locals after adding instructions"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public OooOOOO([B)V
    .locals 2

    if-eqz p1, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/t01;->OooO0o0:Ljava/lang/Object;

    check-cast v0, [B

    if-eq p1, v0, :cond_1

    array-length v1, p1

    array-length v0, v0

    if-lt v1, v0, :cond_0

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Trying to release buffer smaller than original"

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    :goto_0
    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/t01;->OooO0o0:Ljava/lang/Object;

    iget-object v0, p0, Llyiahf/vczjk/t01;->OooO0Oo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/bj0;

    iget-object v0, v0, Llyiahf/vczjk/bj0;->OooO00o:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    const/4 v1, 0x0

    invoke-virtual {v0, v1, p1}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->set(ILjava/lang/Object;)V

    :cond_2
    return-void
.end method

.method public OooOOOo(Llyiahf/vczjk/m35;)V
    .locals 5

    iget-object v0, p1, Llyiahf/vczjk/m35;->OooO00o:Llyiahf/vczjk/b4a;

    iget-object v1, p0, Llyiahf/vczjk/t01;->OooO0O0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/zi5;

    iget-object v2, v1, Llyiahf/vczjk/zi5;->OooO0O0:Llyiahf/vczjk/b4a;

    invoke-virtual {v0, v2}, Llyiahf/vczjk/b4a;->equals(Ljava/lang/Object;)Z

    move-result v0

    iget-object v2, p1, Llyiahf/vczjk/m35;->OooO00o:Llyiahf/vczjk/b4a;

    if-eqz v0, :cond_6

    new-instance v0, Llyiahf/vczjk/ww6;

    iget-object v1, v2, Llyiahf/vczjk/b4a;->OooO0O0:Llyiahf/vczjk/p1a;

    sget-object v2, Llyiahf/vczjk/kv7;->OooO00o:Llyiahf/vczjk/dv7;

    invoke-virtual {v1}, Llyiahf/vczjk/p1a;->OooO0O0()I

    move-result v2

    const/4 v3, 0x0

    if-eqz v2, :cond_5

    const/16 v4, 0x9

    if-eq v2, v4, :cond_4

    const/4 v4, 0x4

    if-eq v2, v4, :cond_3

    const/4 v4, 0x5

    if-eq v2, v4, :cond_2

    const/4 v4, 0x6

    if-eq v2, v4, :cond_1

    const/4 v4, 0x7

    if-ne v2, v4, :cond_0

    sget-object v1, Llyiahf/vczjk/kv7;->o0000Oo:Llyiahf/vczjk/dv7;

    goto :goto_0

    :cond_0
    invoke-static {v1}, Llyiahf/vczjk/kv7;->OooO00o(Llyiahf/vczjk/f3a;)V

    throw v3

    :cond_1
    sget-object v1, Llyiahf/vczjk/kv7;->o0000Oo0:Llyiahf/vczjk/dv7;

    goto :goto_0

    :cond_2
    sget-object v1, Llyiahf/vczjk/kv7;->o0000OoO:Llyiahf/vczjk/dv7;

    goto :goto_0

    :cond_3
    sget-object v1, Llyiahf/vczjk/kv7;->o0000o0:Llyiahf/vczjk/dv7;

    goto :goto_0

    :cond_4
    sget-object v1, Llyiahf/vczjk/kv7;->o0000o0O:Llyiahf/vczjk/dv7;

    goto :goto_0

    :cond_5
    sget-object v1, Llyiahf/vczjk/kv7;->o0000OOo:Llyiahf/vczjk/dv7;

    :goto_0
    invoke-virtual {p1}, Llyiahf/vczjk/m35;->OooO00o()Llyiahf/vczjk/sn7;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/tn7;->OooO0oo(Llyiahf/vczjk/sn7;)Llyiahf/vczjk/tn7;

    move-result-object p1

    iget-object v2, p0, Llyiahf/vczjk/t01;->OooO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/ay8;

    invoke-direct {v0, v1, v2, v3, p1}, Llyiahf/vczjk/ww6;-><init>(Llyiahf/vczjk/dv7;Llyiahf/vczjk/ay8;Llyiahf/vczjk/sn7;Llyiahf/vczjk/tn7;)V

    invoke-virtual {p0, v0, v3}, Llyiahf/vczjk/t01;->OooO0O0(Llyiahf/vczjk/g14;Llyiahf/vczjk/nm4;)V

    return-void

    :cond_6
    new-instance p1, Ljava/lang/IllegalArgumentException;

    iget-object v0, v1, Llyiahf/vczjk/zi5;->OooO0O0:Llyiahf/vczjk/b4a;

    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    invoke-static {v2}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v1

    const-string v2, "declared "

    const-string v3, " but returned "

    invoke-static {v2, v0, v3, v1}, Llyiahf/vczjk/ii5;->OooO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public OooOOo0()V
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/t01;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/zi5;

    iget-object v1, v0, Llyiahf/vczjk/zi5;->OooO0O0:Llyiahf/vczjk/b4a;

    sget-object v2, Llyiahf/vczjk/b4a;->OooOO0o:Llyiahf/vczjk/b4a;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/b4a;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    new-instance v0, Llyiahf/vczjk/ww6;

    sget-object v1, Llyiahf/vczjk/kv7;->o0000OOo:Llyiahf/vczjk/dv7;

    iget-object v2, p0, Llyiahf/vczjk/t01;->OooO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/ay8;

    sget-object v3, Llyiahf/vczjk/tn7;->OooOOOO:Llyiahf/vczjk/tn7;

    const/4 v4, 0x0

    invoke-direct {v0, v1, v2, v4, v3}, Llyiahf/vczjk/ww6;-><init>(Llyiahf/vczjk/dv7;Llyiahf/vczjk/ay8;Llyiahf/vczjk/sn7;Llyiahf/vczjk/tn7;)V

    invoke-virtual {p0, v0, v4}, Llyiahf/vczjk/t01;->OooO0O0(Llyiahf/vczjk/g14;Llyiahf/vczjk/nm4;)V

    return-void

    :cond_0
    new-instance v1, Ljava/lang/IllegalArgumentException;

    iget-object v0, v0, Llyiahf/vczjk/zi5;->OooO0O0:Llyiahf/vczjk/b4a;

    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    const-string v2, "declared "

    const-string v3, " but returned void"

    invoke-static {v2, v0, v3}, Llyiahf/vczjk/u81;->OooOOO0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v1
.end method
