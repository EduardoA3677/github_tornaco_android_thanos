.class public final Llyiahf/vczjk/sr4;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/tr4;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/tr4;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/sr4;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/sr4;->OooOOO:Llyiahf/vczjk/tr4;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 7

    iget v0, p0, Llyiahf/vczjk/sr4;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    iget-object v1, p0, Llyiahf/vczjk/sr4;->OooOOO:Llyiahf/vczjk/tr4;

    iget-object v1, v1, Llyiahf/vczjk/tr4;->OooOo:Llyiahf/vczjk/o45;

    sget-object v2, Llyiahf/vczjk/tr4;->OooOoo0:[Llyiahf/vczjk/th4;

    const/4 v3, 0x0

    aget-object v2, v2, v3

    invoke-static {v1, v2}, Llyiahf/vczjk/xr6;->OooOO0o(Llyiahf/vczjk/t26;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/util/Map;

    invoke-interface {v1}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    move-result-object v1

    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_4

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/util/Map$Entry;

    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/String;

    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/tm7;

    invoke-static {v3}, Llyiahf/vczjk/rd4;->OooO0OO(Ljava/lang/String;)Llyiahf/vczjk/rd4;

    move-result-object v3

    iget-object v2, v2, Llyiahf/vczjk/tm7;->OooO0O0:Llyiahf/vczjk/fq3;

    iget-object v4, v2, Llyiahf/vczjk/fq3;->OooO0OO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/ik4;

    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    move-result v5

    const/4 v6, 0x2

    if-eq v5, v6, :cond_3

    const/4 v6, 0x5

    if-eq v5, v6, :cond_0

    goto :goto_0

    :cond_0
    sget-object v5, Llyiahf/vczjk/ik4;->OooOo00:Llyiahf/vczjk/ik4;

    if-ne v4, v5, :cond_1

    iget-object v2, v2, Llyiahf/vczjk/fq3;->OooO0oo:Ljava/lang/Object;

    check-cast v2, Ljava/lang/String;

    goto :goto_1

    :cond_1
    const/4 v2, 0x0

    :goto_1
    if-nez v2, :cond_2

    goto :goto_0

    :cond_2
    invoke-static {v2}, Llyiahf/vczjk/rd4;->OooO0OO(Ljava/lang/String;)Llyiahf/vczjk/rd4;

    move-result-object v2

    invoke-virtual {v0, v3, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_0

    :cond_3
    invoke-virtual {v0, v3, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_0

    :cond_4
    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/sr4;->OooOOO:Llyiahf/vczjk/tr4;

    iget-object v0, v0, Llyiahf/vczjk/tr4;->OooOo0O:Llyiahf/vczjk/mm7;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    new-instance v1, Ljava/util/ArrayList;

    const/16 v2, 0xa

    invoke-static {v0, v2}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v0

    invoke-direct {v1, v0}, Ljava/util/ArrayList;-><init>(I)V

    return-object v1

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/sr4;->OooOOO:Llyiahf/vczjk/tr4;

    iget-object v1, v0, Llyiahf/vczjk/tr4;->OooOo0o:Llyiahf/vczjk/ld9;

    iget-object v1, v1, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/s64;

    iget-object v0, v0, Llyiahf/vczjk/ih6;->OooOo00:Llyiahf/vczjk/hc3;

    iget-object v0, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    iget-object v0, v0, Llyiahf/vczjk/ic3;->OooO00o:Ljava/lang/String;

    iget-object v1, v1, Llyiahf/vczjk/s64;->OooOO0o:Llyiahf/vczjk/pp3;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v1, "packageFqName"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    invoke-static {v0}, Llyiahf/vczjk/lc5;->o0OOO0o(Ljava/util/List;)Ljava/util/Map;

    move-result-object v0

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
