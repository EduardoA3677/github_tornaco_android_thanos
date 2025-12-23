.class public final Llyiahf/vczjk/jf4;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/kf4;

.field public final synthetic OooOOO0:I

.field public final OooOOOO:Llyiahf/vczjk/of4;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/kf4;Llyiahf/vczjk/of4;I)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/jf4;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/jf4;->OooOOO:Llyiahf/vczjk/kf4;

    iput-object p2, p0, Llyiahf/vczjk/jf4;->OooOOOO:Llyiahf/vczjk/of4;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/of4;Llyiahf/vczjk/kf4;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/jf4;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/jf4;->OooOOOO:Llyiahf/vczjk/of4;

    iput-object p2, p0, Llyiahf/vczjk/jf4;->OooOOO:Llyiahf/vczjk/kf4;

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 8

    const/4 v0, 0x0

    iget-object v1, p0, Llyiahf/vczjk/jf4;->OooOOOO:Llyiahf/vczjk/of4;

    iget-object v2, p0, Llyiahf/vczjk/jf4;->OooOOO:Llyiahf/vczjk/kf4;

    iget v3, p0, Llyiahf/vczjk/jf4;->OooOOO0:I

    packed-switch v3, :pswitch_data_0

    invoke-virtual {v2}, Llyiahf/vczjk/kf4;->OooO00o()Llyiahf/vczjk/by0;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/gz0;->OooOo0o()Llyiahf/vczjk/n3a;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/n3a;->OooO0O0()Ljava/util/Collection;

    move-result-object v0

    const-string v3, "getSupertypes(...)"

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v3, Ljava/util/ArrayList;

    invoke-interface {v0}, Ljava/util/Collection;->size()I

    move-result v4

    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(I)V

    check-cast v0, Ljava/lang/Iterable;

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/uk4;

    new-instance v5, Llyiahf/vczjk/di4;

    invoke-static {v4}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    new-instance v6, Llyiahf/vczjk/o0O0000O;

    const/4 v7, 0x2

    invoke-direct {v6, v4, v2, v7, v1}, Llyiahf/vczjk/o0O0000O;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-direct {v5, v4, v6}, Llyiahf/vczjk/di4;-><init>(Llyiahf/vczjk/uk4;Llyiahf/vczjk/le3;)V

    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_0
    invoke-virtual {v2}, Llyiahf/vczjk/kf4;->OooO00o()Llyiahf/vczjk/by0;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/hk4;->OooO0o0:Llyiahf/vczjk/qt5;

    sget-object v1, Llyiahf/vczjk/w09;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-static {v0, v1}, Llyiahf/vczjk/hk4;->OooO0O0(Llyiahf/vczjk/by0;Llyiahf/vczjk/ic3;)Z

    move-result v1

    if-nez v1, :cond_5

    sget-object v1, Llyiahf/vczjk/w09;->OooO0O0:Llyiahf/vczjk/ic3;

    invoke-static {v0, v1}, Llyiahf/vczjk/hk4;->OooO0O0(Llyiahf/vczjk/by0;Llyiahf/vczjk/ic3;)Z

    move-result v0

    if-eqz v0, :cond_1

    goto :goto_3

    :cond_1
    invoke-virtual {v3}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_3
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_4

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/di4;

    iget-object v1, v1, Llyiahf/vczjk/di4;->OooO00o:Llyiahf/vczjk/uk4;

    invoke-static {v1}, Llyiahf/vczjk/n72;->OooO0OO(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/by0;

    move-result-object v1

    invoke-interface {v1}, Llyiahf/vczjk/by0;->getKind()Llyiahf/vczjk/ly0;

    move-result-object v1

    const-string v4, "getKind(...)"

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v4, Llyiahf/vczjk/ly0;->OooOOO:Llyiahf/vczjk/ly0;

    if-eq v1, v4, :cond_3

    sget-object v4, Llyiahf/vczjk/ly0;->OooOOo0:Llyiahf/vczjk/ly0;

    if-ne v1, v4, :cond_5

    goto :goto_1

    :cond_4
    :goto_2
    new-instance v0, Llyiahf/vczjk/di4;

    invoke-virtual {v2}, Llyiahf/vczjk/kf4;->OooO00o()Llyiahf/vczjk/by0;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/p72;->OooO0o0(Llyiahf/vczjk/v02;)Llyiahf/vczjk/hk4;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/hk4;->OooO0o0()Llyiahf/vczjk/dp8;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/dk0;->OooOo0O:Llyiahf/vczjk/dk0;

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/di4;-><init>(Llyiahf/vczjk/uk4;Llyiahf/vczjk/le3;)V

    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_5
    :goto_3
    invoke-static {v3}, Llyiahf/vczjk/t51;->OooOo0(Ljava/util/ArrayList;)Ljava/util/List;

    move-result-object v0

    return-object v0

    :pswitch_0
    invoke-virtual {v2}, Llyiahf/vczjk/kf4;->OooO00o()Llyiahf/vczjk/by0;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/by0;->OooOo00()Ljava/util/List;

    move-result-object v0

    const-string v2, "getDeclaredTypeParameters(...)"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v2, Ljava/util/ArrayList;

    const/16 v3, 0xa

    invoke-static {v0, v3}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v3

    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_4
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_6

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/t4a;

    new-instance v4, Llyiahf/vczjk/fi4;

    invoke-static {v3}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-direct {v4, v1, v3}, Llyiahf/vczjk/fi4;-><init>(Llyiahf/vczjk/gi4;Llyiahf/vczjk/t4a;)V

    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_4

    :cond_6
    return-object v2

    :pswitch_1
    invoke-virtual {v2}, Llyiahf/vczjk/kf4;->OooO00o()Llyiahf/vczjk/by0;

    move-result-object v2

    invoke-interface {v2}, Llyiahf/vczjk/by0;->getKind()Llyiahf/vczjk/ly0;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/ly0;->OooOOo:Llyiahf/vczjk/ly0;

    if-eq v3, v4, :cond_7

    goto :goto_6

    :cond_7
    invoke-interface {v2}, Llyiahf/vczjk/by0;->OooOo()Z

    move-result v3

    if-eqz v3, :cond_8

    sget-object v3, Llyiahf/vczjk/r51;->OooO00o:Ljava/util/LinkedHashSet;

    invoke-static {v2}, Llyiahf/vczjk/jp8;->Oooo000(Llyiahf/vczjk/by0;)Z

    move-result v3

    if-nez v3, :cond_8

    iget-object v1, v1, Llyiahf/vczjk/of4;->OooOOO:Ljava/lang/Class;

    invoke-virtual {v1}, Ljava/lang/Class;->getEnclosingClass()Ljava/lang/Class;

    move-result-object v1

    invoke-interface {v2}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v2

    invoke-virtual {v2}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    move-result-object v1

    goto :goto_5

    :cond_8
    iget-object v1, v1, Llyiahf/vczjk/of4;->OooOOO:Ljava/lang/Class;

    const-string v2, "INSTANCE"

    invoke-virtual {v1, v2}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    move-result-object v1

    :goto_5
    invoke-virtual {v1, v0}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    const-string v1, "null cannot be cast to non-null type T of kotlin.reflect.jvm.internal.KClassImpl"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    :goto_6
    return-object v0

    :pswitch_2
    iget-object v3, v1, Llyiahf/vczjk/of4;->OooOOO:Ljava/lang/Class;

    invoke-virtual {v3}, Ljava/lang/Class;->isAnonymousClass()Z

    move-result v3

    if-eqz v3, :cond_9

    goto :goto_7

    :cond_9
    invoke-virtual {v1}, Llyiahf/vczjk/of4;->OooOo0()Llyiahf/vczjk/hy0;

    move-result-object v0

    iget-boolean v3, v0, Llyiahf/vczjk/hy0;->OooO0OO:Z

    if-eqz v3, :cond_c

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v0, v1, Llyiahf/vczjk/of4;->OooOOO:Ljava/lang/Class;

    invoke-virtual {v0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0}, Ljava/lang/Class;->getEnclosingMethod()Ljava/lang/reflect/Method;

    move-result-object v2

    const/16 v3, 0x24

    if-eqz v2, :cond_a

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v2}, Ljava/lang/reflect/Method;->getName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v1, v0, v1}, Llyiahf/vczjk/z69;->Oooooo(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    goto :goto_7

    :cond_a
    invoke-virtual {v0}, Ljava/lang/Class;->getEnclosingConstructor()Ljava/lang/reflect/Constructor;

    move-result-object v0

    if-eqz v0, :cond_b

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v0}, Ljava/lang/reflect/Constructor;->getName()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v1, v0, v1}, Llyiahf/vczjk/z69;->Oooooo(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    goto :goto_7

    :cond_b
    invoke-static {v3, v1, v1}, Llyiahf/vczjk/z69;->Oooooo0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    goto :goto_7

    :cond_c
    invoke-virtual {v0}, Llyiahf/vczjk/hy0;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object v0

    const-string v1, "asString(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    :goto_7
    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
