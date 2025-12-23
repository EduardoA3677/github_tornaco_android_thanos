.class public final Llyiahf/vczjk/wn8;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Ljava/lang/String;

.field public final OooO0O0:Ljava/lang/String;

.field public final OooO0OO:Ljava/util/ArrayList;

.field public OooO0Oo:Llyiahf/vczjk/xn6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/a27;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/wn8;->OooO00o:Ljava/lang/String;

    iput-object p3, p0, Llyiahf/vczjk/wn8;->OooO0O0:Ljava/lang/String;

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/wn8;->OooO0OO:Ljava/util/ArrayList;

    new-instance p1, Llyiahf/vczjk/xn6;

    const-string p2, "V"

    const/4 p3, 0x0

    invoke-direct {p1, p2, p3}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    iput-object p1, p0, Llyiahf/vczjk/wn8;->OooO0Oo:Llyiahf/vczjk/xn6;

    return-void
.end method


# virtual methods
.method public final varargs OooO00o(Ljava/lang/String;[Llyiahf/vczjk/f74;)V
    .locals 4

    const-string v0, "type"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/wn8;->OooO0OO:Ljava/util/ArrayList;

    array-length v1, p2

    if-nez v1, :cond_0

    const/4 p2, 0x0

    goto :goto_1

    :cond_0
    new-instance v1, Llyiahf/vczjk/uy;

    new-instance v2, Llyiahf/vczjk/k1;

    const/16 v3, 0x9

    invoke-direct {v2, p2, v3}, Llyiahf/vczjk/k1;-><init>(Ljava/lang/Object;I)V

    const/4 p2, 0x1

    invoke-direct {v1, v2, p2}, Llyiahf/vczjk/uy;-><init>(Ljava/lang/Object;I)V

    const/16 p2, 0xa

    invoke-static {v1, p2}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result p2

    invoke-static {p2}, Llyiahf/vczjk/lc5;->o00oO0o(I)I

    move-result p2

    const/16 v2, 0x10

    if-ge p2, v2, :cond_1

    move p2, v2

    :cond_1
    new-instance v2, Ljava/util/LinkedHashMap;

    invoke-direct {v2, p2}, Ljava/util/LinkedHashMap;-><init>(I)V

    invoke-virtual {v1}, Llyiahf/vczjk/uy;->iterator()Ljava/util/Iterator;

    move-result-object p2

    :goto_0
    move-object v1, p2

    check-cast v1, Llyiahf/vczjk/zi2;

    iget-object v3, v1, Llyiahf/vczjk/zi2;->OooOOO:Ljava/util/Iterator;

    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_2

    invoke-virtual {v1}, Llyiahf/vczjk/zi2;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/kx3;

    iget v3, v1, Llyiahf/vczjk/kx3;->OooO00o:I

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    iget-object v1, v1, Llyiahf/vczjk/kx3;->OooO0O0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/f74;

    invoke-interface {v2, v3, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_0

    :cond_2
    new-instance p2, Llyiahf/vczjk/x3a;

    invoke-direct {p2, v2}, Llyiahf/vczjk/x3a;-><init>(Ljava/util/LinkedHashMap;)V

    :goto_1
    new-instance v1, Llyiahf/vczjk/xn6;

    invoke-direct {v1, p1, p2}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-void
.end method

.method public final varargs OooO0O0(Ljava/lang/String;[Llyiahf/vczjk/f74;)V
    .locals 3

    const-string v0, "type"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/uy;

    new-instance v1, Llyiahf/vczjk/k1;

    const/16 v2, 0x9

    invoke-direct {v1, p2, v2}, Llyiahf/vczjk/k1;-><init>(Ljava/lang/Object;I)V

    const/4 p2, 0x1

    invoke-direct {v0, v1, p2}, Llyiahf/vczjk/uy;-><init>(Ljava/lang/Object;I)V

    const/16 p2, 0xa

    invoke-static {v0, p2}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result p2

    invoke-static {p2}, Llyiahf/vczjk/lc5;->o00oO0o(I)I

    move-result p2

    const/16 v1, 0x10

    if-ge p2, v1, :cond_0

    move p2, v1

    :cond_0
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1, p2}, Ljava/util/LinkedHashMap;-><init>(I)V

    invoke-virtual {v0}, Llyiahf/vczjk/uy;->iterator()Ljava/util/Iterator;

    move-result-object p2

    :goto_0
    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/zi2;

    iget-object v2, v0, Llyiahf/vczjk/zi2;->OooOOO:Ljava/util/Iterator;

    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/zi2;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/kx3;

    iget v2, v0, Llyiahf/vczjk/kx3;->OooO00o:I

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    iget-object v0, v0, Llyiahf/vczjk/kx3;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/f74;

    invoke-interface {v1, v2, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_0

    :cond_1
    new-instance p2, Llyiahf/vczjk/x3a;

    invoke-direct {p2, v1}, Llyiahf/vczjk/x3a;-><init>(Ljava/util/LinkedHashMap;)V

    new-instance v0, Llyiahf/vczjk/xn6;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    iput-object v0, p0, Llyiahf/vczjk/wn8;->OooO0Oo:Llyiahf/vczjk/xn6;

    return-void
.end method

.method public final OooO0OO(Llyiahf/vczjk/ee4;)V
    .locals 2

    const-string v0, "type"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1}, Llyiahf/vczjk/ee4;->OooO0OO()Ljava/lang/String;

    move-result-object p1

    const-string v0, "getDesc(...)"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/xn6;

    const/4 v1, 0x0

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    iput-object v0, p0, Llyiahf/vczjk/wn8;->OooO0Oo:Llyiahf/vczjk/xn6;

    return-void
.end method
