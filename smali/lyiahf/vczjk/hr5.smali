.class public final Llyiahf/vczjk/hr5;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Ljava/util/concurrent/CopyOnWriteArrayList;

.field public final OooO0O0:Llyiahf/vczjk/s29;

.field public final OooO0OO:Llyiahf/vczjk/gh7;


# direct methods
.method public constructor <init>()V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/util/concurrent/CopyOnWriteArrayList;

    invoke-direct {v0}, Ljava/util/concurrent/CopyOnWriteArrayList;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/hr5;->OooO00o:Ljava/util/concurrent/CopyOnWriteArrayList;

    const/4 v0, 0x0

    invoke-static {v0}, Llyiahf/vczjk/r02;->OooO0Oo(Ljava/lang/Object;)Llyiahf/vczjk/s29;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/hr5;->OooO0O0:Llyiahf/vczjk/s29;

    new-instance v1, Llyiahf/vczjk/gh7;

    invoke-direct {v1, v0}, Llyiahf/vczjk/gh7;-><init>(Llyiahf/vczjk/rs5;)V

    iput-object v1, p0, Llyiahf/vczjk/hr5;->OooO0OO:Llyiahf/vczjk/gh7;

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/hr5;Llyiahf/vczjk/k41;Llyiahf/vczjk/r25;Llyiahf/vczjk/r25;)Llyiahf/vczjk/k41;
    .locals 10

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object p0, Llyiahf/vczjk/p25;->OooO0OO:Llyiahf/vczjk/p25;

    if-eqz p1, :cond_0

    iget-object v0, p1, Llyiahf/vczjk/k41;->OooO00o:Llyiahf/vczjk/q25;

    if-nez v0, :cond_1

    :cond_0
    move-object v0, p0

    :cond_1
    iget-object v1, p2, Llyiahf/vczjk/r25;->OooO00o:Llyiahf/vczjk/q25;

    const/4 v2, 0x0

    if-eqz p3, :cond_2

    iget-object v3, p3, Llyiahf/vczjk/r25;->OooO00o:Llyiahf/vczjk/q25;

    goto :goto_0

    :cond_2
    move-object v3, v2

    :goto_0
    invoke-static {v0, v1, v1, v3}, Llyiahf/vczjk/hr5;->OooO0O0(Llyiahf/vczjk/q25;Llyiahf/vczjk/q25;Llyiahf/vczjk/q25;Llyiahf/vczjk/q25;)Llyiahf/vczjk/q25;

    move-result-object v5

    if-eqz p1, :cond_3

    iget-object v0, p1, Llyiahf/vczjk/k41;->OooO0O0:Llyiahf/vczjk/q25;

    if-nez v0, :cond_4

    :cond_3
    move-object v0, p0

    :cond_4
    if-eqz p3, :cond_5

    iget-object v1, p3, Llyiahf/vczjk/r25;->OooO0O0:Llyiahf/vczjk/q25;

    goto :goto_1

    :cond_5
    move-object v1, v2

    :goto_1
    iget-object v3, p2, Llyiahf/vczjk/r25;->OooO0O0:Llyiahf/vczjk/q25;

    iget-object v4, p2, Llyiahf/vczjk/r25;->OooO00o:Llyiahf/vczjk/q25;

    invoke-static {v0, v4, v3, v1}, Llyiahf/vczjk/hr5;->OooO0O0(Llyiahf/vczjk/q25;Llyiahf/vczjk/q25;Llyiahf/vczjk/q25;Llyiahf/vczjk/q25;)Llyiahf/vczjk/q25;

    move-result-object v6

    if-eqz p1, :cond_7

    iget-object p1, p1, Llyiahf/vczjk/k41;->OooO0OO:Llyiahf/vczjk/q25;

    if-nez p1, :cond_6

    goto :goto_2

    :cond_6
    move-object p0, p1

    :cond_7
    :goto_2
    if-eqz p3, :cond_8

    iget-object v2, p3, Llyiahf/vczjk/r25;->OooO0OO:Llyiahf/vczjk/q25;

    :cond_8
    iget-object p1, p2, Llyiahf/vczjk/r25;->OooO0OO:Llyiahf/vczjk/q25;

    invoke-static {p0, v4, p1, v2}, Llyiahf/vczjk/hr5;->OooO0O0(Llyiahf/vczjk/q25;Llyiahf/vczjk/q25;Llyiahf/vczjk/q25;Llyiahf/vczjk/q25;)Llyiahf/vczjk/q25;

    move-result-object v7

    new-instance v4, Llyiahf/vczjk/k41;

    move-object v8, p2

    move-object v9, p3

    invoke-direct/range {v4 .. v9}, Llyiahf/vczjk/k41;-><init>(Llyiahf/vczjk/q25;Llyiahf/vczjk/q25;Llyiahf/vczjk/q25;Llyiahf/vczjk/r25;Llyiahf/vczjk/r25;)V

    return-object v4
.end method

.method public static OooO0O0(Llyiahf/vczjk/q25;Llyiahf/vczjk/q25;Llyiahf/vczjk/q25;Llyiahf/vczjk/q25;)Llyiahf/vczjk/q25;
    .locals 0

    if-nez p3, :cond_0

    return-object p2

    :cond_0
    instance-of p2, p0, Llyiahf/vczjk/o25;

    if-eqz p2, :cond_2

    instance-of p1, p1, Llyiahf/vczjk/p25;

    if-eqz p1, :cond_1

    instance-of p1, p3, Llyiahf/vczjk/p25;

    if-eqz p1, :cond_1

    return-object p3

    :cond_1
    return-object p0

    :cond_2
    return-object p3
.end method


# virtual methods
.method public final OooO0OO(Llyiahf/vczjk/oe3;)V
    .locals 4

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/hr5;->OooO0O0:Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v1

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/k41;

    invoke-interface {p1, v2}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/k41;

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_1

    invoke-virtual {v0, v1, v3}, Llyiahf/vczjk/s29;->OooOOO(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    if-eqz v3, :cond_1

    iget-object p1, p0, Llyiahf/vczjk/hr5;->OooO00o:Ljava/util/concurrent/CopyOnWriteArrayList;

    invoke-virtual {p1}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/oe3;

    invoke-interface {v0, v3}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_0

    :cond_1
    return-void
.end method

.method public final OooO0Oo(Llyiahf/vczjk/r25;Llyiahf/vczjk/r25;)V
    .locals 1

    const-string v0, "sourceLoadStates"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/fr5;

    invoke-direct {v0, p0, p1, p2}, Llyiahf/vczjk/fr5;-><init>(Llyiahf/vczjk/hr5;Llyiahf/vczjk/r25;Llyiahf/vczjk/r25;)V

    invoke-virtual {p0, v0}, Llyiahf/vczjk/hr5;->OooO0OO(Llyiahf/vczjk/oe3;)V

    return-void
.end method
