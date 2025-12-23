.class public final Llyiahf/vczjk/vl;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/ga;

.field public final OooO0O0:Llyiahf/vczjk/da;

.field public final OooO0OO:Llyiahf/vczjk/il;

.field public final OooO0Oo:Llyiahf/vczjk/il;

.field public final OooO0o:Ljava/util/LinkedHashSet;

.field public final OooO0o0:Llyiahf/vczjk/il;

.field public final OooO0oO:Ljava/util/LinkedHashSet;

.field public final OooO0oo:Ljava/util/LinkedHashSet;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ga;Llyiahf/vczjk/da;)V
    .locals 10

    const/4 v0, 0x3

    const/4 v1, 0x0

    const/4 v2, 0x2

    const/4 v3, 0x1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/vl;->OooO00o:Llyiahf/vczjk/ga;

    iput-object p2, p0, Llyiahf/vczjk/vl;->OooO0O0:Llyiahf/vczjk/da;

    new-instance p1, Llyiahf/vczjk/il;

    new-instance p2, Llyiahf/vczjk/rl;

    invoke-direct {p2, p0}, Llyiahf/vczjk/rl;-><init>(Llyiahf/vczjk/vl;)V

    const/4 v4, 0x4

    invoke-direct {p1, p2, v4}, Llyiahf/vczjk/il;-><init>(Llyiahf/vczjk/oe3;I)V

    iput-object p1, p0, Llyiahf/vczjk/vl;->OooO0OO:Llyiahf/vczjk/il;

    new-instance p2, Llyiahf/vczjk/il;

    new-instance v4, Llyiahf/vczjk/ol;

    invoke-direct {v4, p0}, Llyiahf/vczjk/ol;-><init>(Llyiahf/vczjk/vl;)V

    invoke-direct {p2, v4, v3}, Llyiahf/vczjk/il;-><init>(Llyiahf/vczjk/oe3;I)V

    iput-object p2, p0, Llyiahf/vczjk/vl;->OooO0Oo:Llyiahf/vczjk/il;

    new-instance v4, Llyiahf/vczjk/il;

    new-instance v5, Llyiahf/vczjk/pl;

    invoke-direct {v5, p0}, Llyiahf/vczjk/pl;-><init>(Llyiahf/vczjk/vl;)V

    invoke-direct {v4, v5, v2}, Llyiahf/vczjk/il;-><init>(Llyiahf/vczjk/oe3;I)V

    iput-object v4, p0, Llyiahf/vczjk/vl;->OooO0o0:Llyiahf/vczjk/il;

    new-array v5, v2, [Llyiahf/vczjk/ml;

    aput-object p1, v5, v1

    aput-object v4, v5, v3

    invoke-static {v5}, Llyiahf/vczjk/sy;->o0000O0O([Ljava/lang/Object;)Ljava/util/Set;

    move-result-object p1

    sget-boolean v4, Llyiahf/vczjk/xi;->OooO0Oo:Z

    sget-object v5, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    if-eqz v4, :cond_0

    new-instance v4, Llyiahf/vczjk/il;

    new-instance v6, Llyiahf/vczjk/nl;

    invoke-direct {v6, p0}, Llyiahf/vczjk/nl;-><init>(Llyiahf/vczjk/vl;)V

    invoke-direct {v4, v6, v1}, Llyiahf/vczjk/il;-><init>(Llyiahf/vczjk/oe3;I)V

    invoke-static {v4}, Llyiahf/vczjk/tp6;->Oooo0OO(Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v4

    check-cast v4, Ljava/util/Collection;

    goto :goto_0

    :cond_0
    move-object v4, v5

    :goto_0
    check-cast v4, Ljava/lang/Iterable;

    invoke-static {p1, v4}, Llyiahf/vczjk/mh8;->OoooOO0(Ljava/util/Set;Ljava/lang/Iterable;)Ljava/util/LinkedHashSet;

    move-result-object p1

    sget-boolean v4, Llyiahf/vczjk/ly3;->OooO0O0:Z

    sget-object v6, Llyiahf/vczjk/gn2;->OooOOO0:Llyiahf/vczjk/gn2;

    if-eqz v4, :cond_1

    new-instance v4, Llyiahf/vczjk/il;

    new-instance v7, Llyiahf/vczjk/ql;

    invoke-direct {v7, p0}, Llyiahf/vczjk/ql;-><init>(Llyiahf/vczjk/vl;)V

    invoke-direct {v4, v7, v0}, Llyiahf/vczjk/il;-><init>(Llyiahf/vczjk/oe3;I)V

    invoke-static {v4}, Llyiahf/vczjk/tp6;->Oooo0OO(Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v4

    goto :goto_1

    :cond_1
    move-object v4, v6

    :goto_1
    check-cast v4, Ljava/lang/Iterable;

    invoke-static {p1, v4}, Llyiahf/vczjk/mh8;->OoooOO0(Ljava/util/Set;Ljava/lang/Iterable;)Ljava/util/LinkedHashSet;

    move-result-object p1

    sget-boolean v4, Llyiahf/vczjk/yi;->OooO0O0:Z

    if-eqz v4, :cond_2

    invoke-static {p2}, Llyiahf/vczjk/tp6;->Oooo0OO(Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v6

    :cond_2
    check-cast v6, Ljava/lang/Iterable;

    invoke-static {p1, v6}, Llyiahf/vczjk/mh8;->OoooOO0(Ljava/util/Set;Ljava/lang/Iterable;)Ljava/util/LinkedHashSet;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/vl;->OooO0o:Ljava/util/LinkedHashSet;

    sget-boolean v4, Llyiahf/vczjk/daa;->OooO00o:Z

    if-eqz v4, :cond_3

    new-instance v4, Llyiahf/vczjk/hl;

    new-instance v5, Llyiahf/vczjk/sl;

    invoke-direct {v5, p0}, Llyiahf/vczjk/sl;-><init>(Llyiahf/vczjk/vl;)V

    invoke-direct {v4, v5}, Llyiahf/vczjk/ml;-><init>(Llyiahf/vczjk/oe3;)V

    new-instance v5, Llyiahf/vczjk/kl;

    new-instance v6, Llyiahf/vczjk/tl;

    invoke-direct {v6, p0}, Llyiahf/vczjk/tl;-><init>(Llyiahf/vczjk/vl;)V

    sget-object v7, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    const-class v8, Llyiahf/vczjk/fg9;

    invoke-virtual {v7, v8}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v8

    invoke-direct {v5, v8, v6}, Llyiahf/vczjk/kl;-><init>(Llyiahf/vczjk/gf4;Llyiahf/vczjk/oe3;)V

    new-instance v6, Llyiahf/vczjk/kl;

    new-instance v8, Llyiahf/vczjk/ul;

    invoke-direct {v8, p0}, Llyiahf/vczjk/ul;-><init>(Llyiahf/vczjk/vl;)V

    const-class v9, Llyiahf/vczjk/s02;

    invoke-virtual {v7, v9}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v7

    invoke-direct {v6, v7, v8}, Llyiahf/vczjk/kl;-><init>(Llyiahf/vczjk/gf4;Llyiahf/vczjk/oe3;)V

    new-array v0, v0, [Llyiahf/vczjk/ml;

    aput-object v4, v0, v1

    aput-object v5, v0, v3

    aput-object v6, v0, v2

    invoke-static {v0}, Llyiahf/vczjk/sy;->o0000O0O([Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v0

    move-object v5, v0

    check-cast v5, Ljava/util/Collection;

    :cond_3
    check-cast v5, Ljava/lang/Iterable;

    invoke-static {p1, v5}, Llyiahf/vczjk/mh8;->OoooOO0(Ljava/util/Set;Ljava/lang/Iterable;)Ljava/util/LinkedHashSet;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/vl;->OooO0oO:Ljava/util/LinkedHashSet;

    invoke-static {p2}, Llyiahf/vczjk/tp6;->Oooo0OO(Ljava/lang/Object;)Ljava/util/Set;

    move-result-object p2

    check-cast p2, Ljava/lang/Iterable;

    invoke-static {p1, p2}, Llyiahf/vczjk/mh8;->OoooOO0(Ljava/util/Set;Ljava/lang/Iterable;)Ljava/util/LinkedHashSet;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/vl;->OooO0oo:Ljava/util/LinkedHashSet;

    return-void
.end method
