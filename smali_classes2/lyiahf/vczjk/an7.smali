.class public Llyiahf/vczjk/an7;
.super Llyiahf/vczjk/zm7;
.source "SourceFile"


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static OooOO0(Llyiahf/vczjk/go0;)Llyiahf/vczjk/yf4;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/go0;->OooOO0O()Llyiahf/vczjk/uf4;

    move-result-object p0

    instance-of v0, p0, Llyiahf/vczjk/yf4;

    if-eqz v0, :cond_0

    check-cast p0, Llyiahf/vczjk/yf4;

    return-object p0

    :cond_0
    sget-object p0, Llyiahf/vczjk/vm2;->OooOOO:Llyiahf/vczjk/vm2;

    return-object p0
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/rm4;)Ljava/lang/String;
    .locals 0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/an7;->OooO0oo(Llyiahf/vczjk/lf3;)Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method

.method public final OooO00o(Llyiahf/vczjk/vf3;)Llyiahf/vczjk/zf4;
    .locals 6

    new-instance v0, Llyiahf/vczjk/bg4;

    invoke-static {p1}, Llyiahf/vczjk/an7;->OooOO0(Llyiahf/vczjk/go0;)Llyiahf/vczjk/yf4;

    move-result-object v1

    invoke-virtual {p1}, Llyiahf/vczjk/go0;->getName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p1}, Llyiahf/vczjk/go0;->OooOO0o()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {p1}, Llyiahf/vczjk/go0;->OooO0oo()Ljava/lang/Object;

    move-result-object v5

    const-string p1, "container"

    invoke-static {v1, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p1, "name"

    invoke-static {v2, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p1, "signature"

    invoke-static {v3, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v4, 0x0

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/bg4;-><init>(Llyiahf/vczjk/yf4;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/rf3;Ljava/lang/Object;)V

    return-object v0
.end method

.method public final OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;
    .locals 0

    invoke-static {p1}, Llyiahf/vczjk/rn0;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/of4;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0OO(Ljava/lang/Class;)Llyiahf/vczjk/uf4;
    .locals 3

    sget-object v0, Llyiahf/vczjk/rn0;->OooO00o:Llyiahf/vczjk/era;

    const-string v0, "jClass"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/rn0;->OooO0O0:Llyiahf/vczjk/era;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v1, v0, Llyiahf/vczjk/era;->OooOOO:Ljava/lang/Object;

    check-cast v1, Ljava/util/concurrent/ConcurrentHashMap;

    invoke-virtual {v1, p1}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    if-nez v2, :cond_1

    iget-object v0, v0, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/oe3;

    invoke-interface {v0, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    invoke-virtual {v1, p1, v2}, Ljava/util/concurrent/ConcurrentHashMap;->putIfAbsent(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    if-nez p1, :cond_0

    goto :goto_0

    :cond_0
    move-object v2, p1

    :cond_1
    :goto_0
    check-cast v2, Llyiahf/vczjk/uf4;

    return-object v2
.end method

.method public final OooO0Oo(Llyiahf/vczjk/ga;)Llyiahf/vczjk/ig4;
    .locals 4

    new-instance v0, Llyiahf/vczjk/kg4;

    invoke-static {p1}, Llyiahf/vczjk/an7;->OooOO0(Llyiahf/vczjk/go0;)Llyiahf/vczjk/yf4;

    move-result-object v1

    invoke-virtual {p1}, Llyiahf/vczjk/go0;->getName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p1}, Llyiahf/vczjk/go0;->OooOO0o()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {p1}, Llyiahf/vczjk/go0;->OooO0oo()Ljava/lang/Object;

    move-result-object p1

    invoke-direct {v0, v1, v2, v3, p1}, Llyiahf/vczjk/kg4;-><init>(Llyiahf/vczjk/yf4;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;)V

    return-object v0
.end method

.method public final OooO0o(Llyiahf/vczjk/n83;)Llyiahf/vczjk/hh4;
    .locals 4

    new-instance v0, Llyiahf/vczjk/kh4;

    invoke-static {p1}, Llyiahf/vczjk/an7;->OooOO0(Llyiahf/vczjk/go0;)Llyiahf/vczjk/yf4;

    move-result-object v1

    invoke-virtual {p1}, Llyiahf/vczjk/go0;->getName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p1}, Llyiahf/vczjk/go0;->OooOO0o()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {p1}, Llyiahf/vczjk/go0;->OooO0oo()Ljava/lang/Object;

    move-result-object p1

    invoke-direct {v0, v1, v2, v3, p1}, Llyiahf/vczjk/kh4;-><init>(Llyiahf/vczjk/yf4;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;)V

    return-object v0
.end method

.method public final OooO0o0(Llyiahf/vczjk/gs5;)Llyiahf/vczjk/mg4;
    .locals 4

    new-instance v0, Llyiahf/vczjk/og4;

    invoke-static {p1}, Llyiahf/vczjk/an7;->OooOO0(Llyiahf/vczjk/go0;)Llyiahf/vczjk/yf4;

    move-result-object v1

    invoke-virtual {p1}, Llyiahf/vczjk/go0;->getName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p1}, Llyiahf/vczjk/go0;->OooOO0o()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {p1}, Llyiahf/vczjk/go0;->OooO0oo()Ljava/lang/Object;

    move-result-object p1

    invoke-direct {v0, v1, v2, v3, p1}, Llyiahf/vczjk/og4;-><init>(Llyiahf/vczjk/yf4;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;)V

    return-object v0
.end method

.method public final OooO0oO(Llyiahf/vczjk/za7;)Llyiahf/vczjk/mh4;
    .locals 4

    new-instance v0, Llyiahf/vczjk/ph4;

    invoke-static {p1}, Llyiahf/vczjk/an7;->OooOO0(Llyiahf/vczjk/go0;)Llyiahf/vczjk/yf4;

    move-result-object v1

    invoke-virtual {p1}, Llyiahf/vczjk/go0;->getName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p1}, Llyiahf/vczjk/go0;->OooOO0o()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {p1}, Llyiahf/vczjk/go0;->OooO0oo()Ljava/lang/Object;

    move-result-object p1

    invoke-direct {v0, v1, v2, v3, p1}, Llyiahf/vczjk/ph4;-><init>(Llyiahf/vczjk/yf4;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;)V

    return-object v0
.end method

.method public final OooO0oo(Llyiahf/vczjk/lf3;)Ljava/lang/String;
    .locals 11

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    const-class v1, Lkotlin/Metadata;

    invoke-virtual {v0, v1}, Ljava/lang/Class;->getAnnotation(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object v0

    check-cast v0, Lkotlin/Metadata;

    const/4 v1, 0x0

    if-nez v0, :cond_0

    goto/16 :goto_0

    :cond_0
    invoke-interface {v0}, Lkotlin/Metadata;->d1()[Ljava/lang/String;

    move-result-object v2

    array-length v3, v2

    if-nez v3, :cond_1

    move-object v2, v1

    :cond_1
    if-nez v2, :cond_2

    goto :goto_0

    :cond_2
    invoke-interface {v0}, Lkotlin/Metadata;->d2()[Ljava/lang/String;

    move-result-object v1

    sget-object v3, Llyiahf/vczjk/ve4;->OooO00o:Llyiahf/vczjk/iu2;

    const-string v3, "strings"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v3, Ljava/io/ByteArrayInputStream;

    invoke-static {v2}, Llyiahf/vczjk/vc0;->OooO00o([Ljava/lang/String;)[B

    move-result-object v2

    invoke-direct {v3, v2}, Ljava/io/ByteArrayInputStream;-><init>([B)V

    new-instance v2, Llyiahf/vczjk/xn6;

    sget-object v4, Llyiahf/vczjk/ve4;->OooO00o:Llyiahf/vczjk/iu2;

    invoke-static {v3, v1}, Llyiahf/vczjk/ve4;->OooO0oO(Ljava/io/ByteArrayInputStream;[Ljava/lang/String;)Llyiahf/vczjk/be4;

    move-result-object v1

    sget-object v4, Llyiahf/vczjk/pc7;->OooOOO:Llyiahf/vczjk/je4;

    sget-object v5, Llyiahf/vczjk/ve4;->OooO00o:Llyiahf/vczjk/iu2;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v6, Llyiahf/vczjk/h11;

    invoke-direct {v6, v3}, Llyiahf/vczjk/h11;-><init>(Ljava/io/InputStream;)V

    invoke-interface {v4, v6, v5}, Llyiahf/vczjk/kp6;->OooO00o(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/pi5;

    const/4 v4, 0x0

    :try_start_0
    invoke-virtual {v6, v4}, Llyiahf/vczjk/h11;->OooO00o(I)V
    :try_end_0
    .catch Llyiahf/vczjk/i44; {:try_start_0 .. :try_end_0} :catch_0

    invoke-static {v3}, Llyiahf/vczjk/je4;->OooO0O0(Llyiahf/vczjk/pi5;)V

    check-cast v3, Llyiahf/vczjk/pc7;

    invoke-direct {v2, v1, v3}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v2}, Llyiahf/vczjk/xn6;->OooO00o()Ljava/lang/Object;

    move-result-object v1

    move-object v7, v1

    check-cast v7, Llyiahf/vczjk/be4;

    invoke-virtual {v2}, Llyiahf/vczjk/xn6;->OooO0O0()Ljava/lang/Object;

    move-result-object v1

    move-object v6, v1

    check-cast v6, Llyiahf/vczjk/pc7;

    new-instance v9, Llyiahf/vczjk/yi5;

    invoke-interface {v0}, Lkotlin/Metadata;->mv()[I

    move-result-object v1

    invoke-interface {v0}, Lkotlin/Metadata;->xi()I

    move-result v0

    and-int/lit8 v0, v0, 0x8

    if-eqz v0, :cond_3

    const/4 v4, 0x1

    :cond_3
    invoke-direct {v9, v1, v4}, Llyiahf/vczjk/yi5;-><init>([IZ)V

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v5

    new-instance v8, Llyiahf/vczjk/h87;

    invoke-virtual {v6}, Llyiahf/vczjk/pc7;->OoooOO0()Llyiahf/vczjk/nd7;

    move-result-object v0

    const-string v1, "getTypeTable(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {v8, v0}, Llyiahf/vczjk/h87;-><init>(Llyiahf/vczjk/nd7;)V

    sget-object v10, Llyiahf/vczjk/vm7;->OooOOO:Llyiahf/vczjk/vm7;

    invoke-static/range {v5 .. v10}, Llyiahf/vczjk/mba;->OooO0o(Ljava/lang/Class;Llyiahf/vczjk/sg3;Llyiahf/vczjk/rt5;Llyiahf/vczjk/h87;Llyiahf/vczjk/zb0;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/co0;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ho8;

    new-instance v1, Llyiahf/vczjk/bg4;

    sget-object v2, Llyiahf/vczjk/vm2;->OooOOO:Llyiahf/vczjk/vm2;

    invoke-direct {v1, v2, v0}, Llyiahf/vczjk/bg4;-><init>(Llyiahf/vczjk/yf4;Llyiahf/vczjk/rf3;)V

    :goto_0
    if-eqz v1, :cond_4

    invoke-static {v1}, Llyiahf/vczjk/mba;->OooO0O0(Ljava/lang/Object;)Llyiahf/vczjk/bg4;

    move-result-object v0

    if-eqz v0, :cond_4

    sget-object p1, Llyiahf/vczjk/en7;->OooO00o:Llyiahf/vczjk/h72;

    invoke-virtual {v0}, Llyiahf/vczjk/bg4;->OooOo0()Llyiahf/vczjk/rf3;

    move-result-object p1

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    invoke-static {v1, p1}, Llyiahf/vczjk/en7;->OooO00o(Ljava/lang/StringBuilder;Llyiahf/vczjk/eo0;)V

    invoke-interface {p1}, Llyiahf/vczjk/co0;->OoooOOO()Ljava/util/List;

    move-result-object v0

    const-string v2, "getValueParameters(...)"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v5, Llyiahf/vczjk/iu6;->OooOo0O:Llyiahf/vczjk/iu6;

    const-string v4, ")"

    const/16 v6, 0x30

    const-string v2, ", "

    const-string v3, "("

    invoke-static/range {v0 .. v6}, Llyiahf/vczjk/d21;->o0ooOOo(Ljava/lang/Iterable;Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;I)V

    const-string v0, " -> "

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-interface {p1}, Llyiahf/vczjk/co0;->OooOOoo()Llyiahf/vczjk/uk4;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-static {p1}, Llyiahf/vczjk/en7;->OooO0Oo(Llyiahf/vczjk/uk4;)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    return-object p1

    :cond_4
    invoke-super {p0, p1}, Llyiahf/vczjk/zm7;->OooO0oo(Llyiahf/vczjk/lf3;)Ljava/lang/String;

    move-result-object p1

    return-object p1

    :catch_0
    move-exception v0

    move-object p1, v0

    invoke-virtual {p1, v3}, Llyiahf/vczjk/i44;->OooO0O0(Llyiahf/vczjk/pi5;)V

    throw p1
.end method
