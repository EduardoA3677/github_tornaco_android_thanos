.class public final Llyiahf/vczjk/a0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/hha;


# instance fields
.field public final synthetic OooO00o:I

.field public final OooO0O0:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/a0;->OooO00o:I

    iput-object p1, p0, Llyiahf/vczjk/a0;->OooO0O0:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>([Llyiahf/vczjk/fha;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Llyiahf/vczjk/a0;->OooO00o:I

    const-string v0, "initializers"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/a0;->OooO0O0:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final OooO0OO(Ljava/lang/Class;Llyiahf/vczjk/ir5;)Llyiahf/vczjk/dha;
    .locals 7

    iget v0, p0, Llyiahf/vczjk/a0;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    invoke-static {p1}, Llyiahf/vczjk/rs;->Oooo0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/a0;->OooO0O0:Ljava/lang/Object;

    check-cast v0, [Llyiahf/vczjk/fha;

    array-length v1, v0

    invoke-static {v0, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/fha;

    const-string v1, "initializers"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    array-length v1, v0

    const/4 v2, 0x0

    :goto_0
    const/4 v3, 0x0

    if-ge v2, v1, :cond_1

    aget-object v4, v0, v2

    iget-object v5, v4, Llyiahf/vczjk/fha;->OooO00o:Llyiahf/vczjk/gf4;

    invoke-static {v5, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_0

    goto :goto_1

    :cond_0
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_1
    move-object v4, v3

    :goto_1
    if-eqz v4, :cond_2

    iget-object v0, v4, Llyiahf/vczjk/fha;->OooO0O0:Llyiahf/vczjk/oe3;

    if-eqz v0, :cond_2

    invoke-interface {v0, p2}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p2

    move-object v3, p2

    check-cast v3, Llyiahf/vczjk/dha;

    :cond_2
    if-eqz v3, :cond_3

    return-object v3

    :cond_3
    new-instance p2, Ljava/lang/StringBuilder;

    const-string v0, "No initializer set for given class "

    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-interface {p1}, Llyiahf/vczjk/gf4;->OooO00o()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    new-instance p2, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p2

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/zs7;

    invoke-direct {v0}, Llyiahf/vczjk/zs7;-><init>()V

    iget-object v1, p0, Llyiahf/vczjk/a0;->OooO0O0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/era;

    invoke-static {p2}, Llyiahf/vczjk/jp8;->OooOOoo(Llyiahf/vczjk/os1;)Llyiahf/vczjk/x58;

    move-result-object v2

    new-instance v3, Llyiahf/vczjk/yv1;

    iget-object v4, v1, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/wv1;

    iget-object v1, v1, Llyiahf/vczjk/era;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/uv1;

    invoke-direct {v3, v4, v1, v2}, Llyiahf/vczjk/yv1;-><init>(Llyiahf/vczjk/wv1;Llyiahf/vczjk/uv1;Llyiahf/vczjk/x58;)V

    const-class v1, Llyiahf/vczjk/rn3;

    invoke-static {v1, v3}, Llyiahf/vczjk/mc4;->OooOoo(Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/rn3;

    check-cast v2, Llyiahf/vczjk/yv1;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v4, "expectedSize"

    const/16 v5, 0x25

    invoke-static {v5, v4}, Llyiahf/vczjk/ng0;->OooOOOO(ILjava/lang/String;)V

    new-instance v4, Llyiahf/vczjk/yw;

    invoke-direct {v4, v5}, Llyiahf/vczjk/yw;-><init>(I)V

    sget v5, Llyiahf/vczjk/m6a;->OooO0oO:I

    iget-object v5, v2, Llyiahf/vczjk/yv1;->OooO0OO:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.oOo00o0o"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    sget v5, Llyiahf/vczjk/r02;->OooOO0o:I

    iget-object v5, v2, Llyiahf/vczjk/yv1;->OooO0Oo:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.w6"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    sget v5, Llyiahf/vczjk/c6a;->OooOooo:I

    iget-object v5, v2, Llyiahf/vczjk/yv1;->OooO0o0:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.dv"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    sget v5, Llyiahf/vczjk/nqa;->OooO0oO:I

    iget-object v5, v2, Llyiahf/vczjk/yv1;->OooO0o:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.aw"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    sget v5, Llyiahf/vczjk/os9;->OooO0o0:I

    iget-object v5, v2, Llyiahf/vczjk/yv1;->OooO0oO:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.i40"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    sget v5, Llyiahf/vczjk/zsa;->OooOO0:I

    iget-object v5, v2, Llyiahf/vczjk/yv1;->OooO0oo:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.g70"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    sget v5, Llyiahf/vczjk/m6a;->OooO0oO:I

    iget-object v5, v2, Llyiahf/vczjk/yv1;->OooO:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.l71"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    sget v5, Llyiahf/vczjk/yi4;->OooO:I

    iget-object v5, v2, Llyiahf/vczjk/yv1;->OooOO0:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.fj1"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    sget v5, Llyiahf/vczjk/l4a;->OooOO0o:I

    iget-object v5, v2, Llyiahf/vczjk/yv1;->OooOO0O:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.lw1"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    sget v5, Llyiahf/vczjk/sb;->OooO:I

    iget-object v5, v2, Llyiahf/vczjk/yv1;->OooOO0o:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.k02"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    sget v5, Llyiahf/vczjk/bua;->OooOO0:I

    iget-object v5, v2, Llyiahf/vczjk/yv1;->OooOOO0:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.on4"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    sget v5, Llyiahf/vczjk/m6a;->OooO0oO:I

    iget-object v5, v2, Llyiahf/vczjk/yv1;->OooOOO:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.l55"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    sget v5, Llyiahf/vczjk/tg0;->OooO0oo:I

    iget-object v5, v2, Llyiahf/vczjk/yv1;->OooOOOO:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.ua5"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    sget v5, Llyiahf/vczjk/e16;->OooOO0O:I

    iget-object v5, v2, Llyiahf/vczjk/yv1;->OooOOOo:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.vw5"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    sget v5, Llyiahf/vczjk/yi4;->OooO:I

    iget-object v5, v2, Llyiahf/vczjk/yv1;->OooOOo0:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.nc6"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    sget v5, Llyiahf/vczjk/l4a;->OooOO0o:I

    iget-object v5, v2, Llyiahf/vczjk/yv1;->OooOOo:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.cf6"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    iget-object v5, v2, Llyiahf/vczjk/yv1;->OooOOoo:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.vr6"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    iget-object v5, v2, Llyiahf/vczjk/yv1;->OooOo00:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.pu6"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    iget-object v5, v2, Llyiahf/vczjk/yv1;->OooOo0:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.gw6"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    iget-object v5, v2, Llyiahf/vczjk/yv1;->OooOo0O:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.a77"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    iget-object v5, v2, Llyiahf/vczjk/yv1;->OooOo0o:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.k77"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    iget-object v5, v2, Llyiahf/vczjk/yv1;->OooOo:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.g87"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    iget-object v5, v2, Llyiahf/vczjk/yv1;->OooOoO0:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.me7"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    iget-object v5, v2, Llyiahf/vczjk/yv1;->OooOoO:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.wi7"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    iget-object v5, v2, Llyiahf/vczjk/yv1;->OooOoOO:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.oy7"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    iget-object v5, v2, Llyiahf/vczjk/yv1;->OooOoo0:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.ny7"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    iget-object v5, v2, Llyiahf/vczjk/yv1;->OooOoo:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.i48"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    iget-object v5, v2, Llyiahf/vczjk/yv1;->OooOooO:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.h48"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    iget-object v5, v2, Llyiahf/vczjk/yv1;->OooOooo:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.dh8"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    iget-object v5, v2, Llyiahf/vczjk/yv1;->Oooo000:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.dj8"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    iget-object v5, v2, Llyiahf/vczjk/yv1;->Oooo00O:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.cj8"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    iget-object v5, v2, Llyiahf/vczjk/yv1;->Oooo00o:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.vm8"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    iget-object v5, v2, Llyiahf/vczjk/yv1;->Oooo0:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.n19"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    iget-object v5, v2, Llyiahf/vczjk/yv1;->Oooo0O0:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.w39"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    iget-object v5, v2, Llyiahf/vczjk/yv1;->Oooo0OO:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.v89"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    iget-object v5, v2, Llyiahf/vczjk/yv1;->Oooo0o0:Llyiahf/vczjk/xv1;

    const-string v6, "lyiahf.vczjk.mka"

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    iget-object v2, v2, Llyiahf/vczjk/yv1;->Oooo0o:Llyiahf/vczjk/xv1;

    const-string v5, "lyiahf.vczjk.bla"

    invoke-virtual {v4, v5, v2}, Llyiahf/vczjk/yw;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v4}, Llyiahf/vczjk/yw;->OooO0o0()Llyiahf/vczjk/ao7;

    move-result-object v2

    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v2, v4}, Llyiahf/vczjk/ao7;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/le7;

    sget-object v4, Llyiahf/vczjk/sn3;->OooO0Oo:Llyiahf/vczjk/ws7;

    iget-object p2, p2, Llyiahf/vczjk/os1;->OooO00o:Ljava/util/LinkedHashMap;

    invoke-virtual {p2, v4}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/oe3;

    invoke-static {v1, v3}, Llyiahf/vczjk/mc4;->OooOoo(Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/rn3;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v1, Llyiahf/vczjk/ao7;->OooOOoo:Llyiahf/vczjk/ao7;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/ao7;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    if-nez v1, :cond_6

    if-nez p2, :cond_5

    if-eqz v2, :cond_4

    invoke-interface {v2}, Llyiahf/vczjk/le7;->get()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/dha;

    goto :goto_2

    :cond_4
    new-instance p2, Ljava/lang/IllegalStateException;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Expected the @HiltViewModel-annotated class "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    const-string v1, " to be available in the multi-binding of @HiltViewModelMap but none was found."

    invoke-static {p1, v0, v1}, Llyiahf/vczjk/ii5;->OooO0oo(Ljava/lang/Class;Ljava/lang/StringBuilder;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p2

    :cond_5
    new-instance p2, Ljava/lang/IllegalStateException;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Found creation callback but class "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    const-string v1, " does not have an assisted factory specified in @HiltViewModel."

    invoke-static {p1, v0, v1}, Llyiahf/vczjk/ii5;->OooO0oo(Ljava/lang/Class;Ljava/lang/StringBuilder;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p2

    :cond_6
    if-nez v2, :cond_a

    if-eqz p2, :cond_9

    invoke-interface {p2, v1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/dha;

    :goto_2
    new-instance p2, Llyiahf/vczjk/pn3;

    invoke-direct {p2, v0}, Llyiahf/vczjk/pn3;-><init>(Llyiahf/vczjk/zs7;)V

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v0, p1, Llyiahf/vczjk/dha;->OooO00o:Llyiahf/vczjk/eha;

    if-eqz v0, :cond_8

    iget-boolean v1, v0, Llyiahf/vczjk/eha;->OooO0Oo:Z

    if-eqz v1, :cond_7

    invoke-static {p2}, Llyiahf/vczjk/eha;->OooO00o(Ljava/lang/AutoCloseable;)V

    goto :goto_3

    :cond_7
    iget-object v1, v0, Llyiahf/vczjk/eha;->OooO00o:Llyiahf/vczjk/pp3;

    monitor-enter v1

    :try_start_0
    iget-object v0, v0, Llyiahf/vczjk/eha;->OooO0OO:Ljava/util/LinkedHashSet;

    invoke-interface {v0, p2}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v1

    goto :goto_3

    :catchall_0
    move-exception p1

    monitor-exit v1

    throw p1

    :cond_8
    :goto_3
    return-object p1

    :cond_9
    new-instance p2, Ljava/lang/IllegalStateException;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Found @HiltViewModel-annotated class "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    const-string v1, " using @AssistedInject but no creation callback was provided in CreationExtras."

    invoke-static {p1, v0, v1}, Llyiahf/vczjk/ii5;->OooO0oo(Ljava/lang/Class;Ljava/lang/StringBuilder;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p2

    :cond_a
    new-instance p2, Ljava/lang/AssertionError;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Found the @HiltViewModel-annotated class "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    const-string v1, " in both the multi-bindings of @HiltViewModelMap and @HiltViewModelAssistedMap."

    invoke-static {p1, v0, v1}, Llyiahf/vczjk/ii5;->OooO0oo(Ljava/lang/Class;Ljava/lang/StringBuilder;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    throw p2

    :pswitch_1
    new-instance p1, Llyiahf/vczjk/as7;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    iput-object p2, p1, Llyiahf/vczjk/as7;->OooOOO0:Ljava/lang/Object;

    iget-object p2, p0, Llyiahf/vczjk/a0;->OooO0O0:Ljava/lang/Object;

    check-cast p2, Landroidx/activity/ComponentActivity;

    const-string v0, "context"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p2}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object p2

    instance-of v0, p2, Landroid/app/Application;

    if-eqz v0, :cond_b

    check-cast p2, Landroid/app/Application;

    goto :goto_4

    :cond_b
    move-object v0, p2

    :cond_c
    instance-of v1, v0, Landroid/content/ContextWrapper;

    if-eqz v1, :cond_d

    check-cast v0, Landroid/content/ContextWrapper;

    invoke-virtual {v0}, Landroid/content/ContextWrapper;->getBaseContext()Landroid/content/Context;

    move-result-object v0

    instance-of v1, v0, Landroid/app/Application;

    if-eqz v1, :cond_c

    move-object p2, v0

    check-cast p2, Landroid/app/Application;

    :goto_4
    const-class v0, Llyiahf/vczjk/b0;

    invoke-static {v0, p2}, Llyiahf/vczjk/mc4;->OooOoo(Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/b0;

    check-cast p2, Llyiahf/vczjk/wv1;

    iget-object p2, p2, Llyiahf/vczjk/wv1;->OooO0O0:Llyiahf/vczjk/wv1;

    new-instance v0, Llyiahf/vczjk/uv1;

    invoke-direct {v0, p2}, Llyiahf/vczjk/uv1;-><init>(Llyiahf/vczjk/wv1;)V

    new-instance p2, Llyiahf/vczjk/c0;

    invoke-direct {p2, v0, p1}, Llyiahf/vczjk/c0;-><init>(Llyiahf/vczjk/uv1;Llyiahf/vczjk/as7;)V

    return-object p2

    :cond_d
    new-instance p1, Ljava/lang/IllegalStateException;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Could not find an Application in the given context: "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
