.class public abstract Llyiahf/vczjk/qu6;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final synthetic OooO00o:I

.field public static final synthetic OooO0O0:I

.field public static final synthetic OooO0OO:I

.field public static volatile OooO0Oo:Llyiahf/vczjk/nl1;

.field public static OooO0o:Llyiahf/vczjk/qv3;

.field public static OooO0o0:Llyiahf/vczjk/qv3;

.field public static final synthetic OooO0oO:I


# direct methods
.method public static final OooO(Ljava/lang/Class;Llyiahf/vczjk/eo0;)Ljava/lang/reflect/Method;
    .locals 3

    const-string v0, "descriptor"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    :try_start_0
    const-string v0, "unbox-impl"

    const/4 v1, 0x0

    invoke-virtual {p0, v0, v1}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/NoSuchMethodException; {:try_start_0 .. :try_end_0} :catch_0

    return-object v0

    :catch_0
    new-instance v0, Llyiahf/vczjk/es1;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "No unbox method found in inline class: "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p0, " (calling "

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 p0, 0x29

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Llyiahf/vczjk/es1;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public static final OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V
    .locals 6

    sget-object v0, Llyiahf/vczjk/wc;->OooOO0O:Llyiahf/vczjk/wc;

    move-object v1, p0

    check-cast v1, Llyiahf/vczjk/zf1;

    iget v2, v1, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-static {p0, p1}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p1

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    iget-object v5, v1, Llyiahf/vczjk/zf1;->OooO00o:Llyiahf/vczjk/ed5;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v5, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v5, :cond_0

    invoke-virtual {v1, v4}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_0

    :cond_0
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_0
    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v0, p0, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v0, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v3, p0, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v0, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {p1, p0, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object p0, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean p1, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez p1, :cond_1

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object p1

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-nez p1, :cond_2

    :cond_1
    invoke-static {v2, v1, v2, p0}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_2
    const/4 p0, 0x1

    invoke-virtual {v1, p0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-void
.end method

.method public static OooO0O0(Ljava/lang/StringBuilder;Ljava/lang/Object;Llyiahf/vczjk/oe3;)V
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    if-eqz p2, :cond_0

    invoke-interface {p2, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/CharSequence;

    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    return-void

    :cond_0
    if-nez p1, :cond_1

    const/4 p2, 0x1

    goto :goto_0

    :cond_1
    instance-of p2, p1, Ljava/lang/CharSequence;

    :goto_0
    if-eqz p2, :cond_2

    check-cast p1, Ljava/lang/CharSequence;

    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    return-void

    :cond_2
    instance-of p2, p1, Ljava/lang/Character;

    if-eqz p2, :cond_3

    check-cast p1, Ljava/lang/Character;

    invoke-virtual {p1}, Ljava/lang/Character;->charValue()C

    move-result p1

    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/Appendable;

    return-void

    :cond_3
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    return-void
.end method

.method public static OooO0OO(Ljava/util/concurrent/Callable;)Llyiahf/vczjk/i88;
    .locals 1

    :try_start_0
    invoke-interface {p0}, Ljava/util/concurrent/Callable;->call()Ljava/lang/Object;

    move-result-object p0

    const-string v0, "Scheduler Callable result can\'t be null"

    invoke-static {p0, v0}, Llyiahf/vczjk/nqa;->Oooo0o0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p0, Llyiahf/vczjk/i88;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-object p0

    :catchall_0
    move-exception p0

    invoke-static {p0}, Llyiahf/vczjk/ur2;->OooO00o(Ljava/lang/Throwable;)Ljava/lang/RuntimeException;

    move-result-object p0

    throw p0
.end method

.method public static OooO0Oo(II)Llyiahf/vczjk/aw7;
    .locals 3

    and-int/lit8 p1, p1, 0x1

    if-eqz p1, :cond_0

    const/16 p0, 0x8

    :cond_0
    const/4 p1, 0x3

    if-lt p0, p1, :cond_1

    sget p1, Llyiahf/vczjk/tba;->OooO0O0:F

    int-to-float v0, p0

    div-float/2addr p1, v0

    float-to-double v0, p1

    invoke-static {v0, v1}, Ljava/lang/Math;->cos(D)D

    move-result-wide v0

    double-to-float p1, v0

    const/high16 v0, 0x3f800000    # 1.0f

    div-float p1, v0, p1

    new-instance v1, Llyiahf/vczjk/jr1;

    const/4 v2, 0x2

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/jr1;-><init>(FI)V

    const/4 v0, 0x0

    invoke-static {p0, p1, v1, v0}, Llyiahf/vczjk/er8;->OooO0Oo(IFLlyiahf/vczjk/jr1;Ljava/util/List;)Llyiahf/vczjk/aw7;

    move-result-object p0

    return-object p0

    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "Circle must have at least three vertices"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static final OooO0o(Llyiahf/vczjk/so0;Llyiahf/vczjk/rf3;Z)Llyiahf/vczjk/so0;
    .locals 3

    const-string v0, "descriptor"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p1}, Llyiahf/vczjk/uz3;->OooO00o(Llyiahf/vczjk/eo0;)Z

    move-result v0

    if-nez v0, :cond_8

    invoke-interface {p1}, Llyiahf/vczjk/co0;->o00Oo0()Ljava/util/List;

    move-result-object v0

    const-string v1, "getContextReceiverParameters(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_0

    goto :goto_0

    :cond_0
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_2

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/mp4;

    invoke-virtual {v1}, Llyiahf/vczjk/mp4;->getType()Llyiahf/vczjk/uk4;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/uz3;->OooO0oO(Llyiahf/vczjk/uk4;)Z

    move-result v1

    if-eqz v1, :cond_1

    goto :goto_2

    :cond_2
    :goto_0
    invoke-interface {p1}, Llyiahf/vczjk/co0;->OoooOOO()Ljava/util/List;

    move-result-object v0

    const-string v1, "getValueParameters(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_3

    goto :goto_1

    :cond_3
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_4
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_5

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/tca;

    check-cast v1, Llyiahf/vczjk/bda;

    invoke-virtual {v1}, Llyiahf/vczjk/bda;->getType()Llyiahf/vczjk/uk4;

    move-result-object v1

    const-string v2, "getType(...)"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v1}, Llyiahf/vczjk/uz3;->OooO0oO(Llyiahf/vczjk/uk4;)Z

    move-result v1

    if-eqz v1, :cond_4

    goto :goto_2

    :cond_5
    :goto_1
    invoke-interface {p1}, Llyiahf/vczjk/co0;->OooOOoo()Llyiahf/vczjk/uk4;

    move-result-object v0

    const/4 v1, 0x1

    if-eqz v0, :cond_6

    invoke-static {v0}, Llyiahf/vczjk/uz3;->OooO0OO(Llyiahf/vczjk/uk4;)Z

    move-result v0

    if-ne v0, v1, :cond_6

    goto :goto_2

    :cond_6
    invoke-static {p1}, Llyiahf/vczjk/qu6;->OooO0oo(Llyiahf/vczjk/eo0;)Llyiahf/vczjk/uk4;

    move-result-object v0

    if-eqz v0, :cond_7

    invoke-static {v0}, Llyiahf/vczjk/uz3;->OooO0oO(Llyiahf/vczjk/uk4;)Z

    move-result v0

    if-ne v0, v1, :cond_7

    goto :goto_2

    :cond_7
    return-object p0

    :cond_8
    :goto_2
    new-instance v0, Llyiahf/vczjk/eca;

    invoke-direct {v0, p0, p1, p2}, Llyiahf/vczjk/eca;-><init>(Llyiahf/vczjk/so0;Llyiahf/vczjk/rf3;Z)V

    return-object v0
.end method

.method public static final OooO0o0(Ljava/lang/Object;Llyiahf/vczjk/eo0;)Ljava/lang/Object;
    .locals 1

    instance-of v0, p1, Llyiahf/vczjk/sa7;

    if-eqz v0, :cond_0

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/ada;

    invoke-static {v0}, Llyiahf/vczjk/uz3;->OooO0o0(Llyiahf/vczjk/ada;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-static {p1}, Llyiahf/vczjk/qu6;->OooO0oo(Llyiahf/vczjk/eo0;)Llyiahf/vczjk/uk4;

    move-result-object v0

    if-eqz v0, :cond_1

    invoke-static {v0}, Llyiahf/vczjk/qu6;->OooOo0O(Llyiahf/vczjk/uk4;)Ljava/lang/Class;

    move-result-object v0

    if-eqz v0, :cond_1

    invoke-static {v0, p1}, Llyiahf/vczjk/qu6;->OooO(Ljava/lang/Class;Llyiahf/vczjk/eo0;)Ljava/lang/reflect/Method;

    move-result-object p1

    const/4 v0, 0x0

    invoke-virtual {p1, p0, v0}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    :cond_1
    :goto_0
    return-object p0
.end method

.method public static final OooO0oO(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/uk4;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v0, p0, Llyiahf/vczjk/p5a;

    if-eqz v0, :cond_0

    check-cast p0, Llyiahf/vczjk/p5a;

    invoke-interface {p0}, Llyiahf/vczjk/p5a;->OooOOOO()Llyiahf/vczjk/uk4;

    move-result-object p0

    return-object p0

    :cond_0
    const/4 p0, 0x0

    return-object p0
.end method

.method public static final OooO0oo(Llyiahf/vczjk/eo0;)Llyiahf/vczjk/uk4;
    .locals 3

    invoke-interface {p0}, Llyiahf/vczjk/co0;->Ooooooo()Llyiahf/vczjk/mp4;

    move-result-object v0

    invoke-interface {p0}, Llyiahf/vczjk/co0;->Oooooo0()Llyiahf/vczjk/mp4;

    move-result-object v1

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/mp4;->getType()Llyiahf/vczjk/uk4;

    move-result-object p0

    return-object p0

    :cond_0
    const/4 v0, 0x0

    if-nez v1, :cond_1

    goto :goto_1

    :cond_1
    instance-of v2, p0, Llyiahf/vczjk/il1;

    if-eqz v2, :cond_2

    invoke-virtual {v1}, Llyiahf/vczjk/mp4;->getType()Llyiahf/vczjk/uk4;

    move-result-object p0

    return-object p0

    :cond_2
    invoke-interface {p0}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object p0

    instance-of v1, p0, Llyiahf/vczjk/by0;

    if-eqz v1, :cond_3

    check-cast p0, Llyiahf/vczjk/by0;

    goto :goto_0

    :cond_3
    move-object p0, v0

    :goto_0
    if-eqz p0, :cond_4

    invoke-interface {p0}, Llyiahf/vczjk/by0;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object p0

    return-object p0

    :cond_4
    :goto_1
    return-object v0
.end method

.method public static final OooOO0(Llyiahf/vczjk/dp8;)Ljava/util/ArrayList;
    .locals 7

    invoke-static {p0}, Llyiahf/vczjk/vt6;->OooOOOO(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/dp8;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/qu6;->OooOO0O(Llyiahf/vczjk/dp8;)Ljava/util/ArrayList;

    move-result-object v0

    const/4 v1, 0x0

    if-eqz v0, :cond_2

    new-instance v2, Ljava/util/ArrayList;

    const/16 v3, 0xa

    invoke-static {v0, v3}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v4

    invoke-direct {v2, v4}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    new-instance v5, Ljava/lang/StringBuilder;

    const-string v6, "unbox-impl-"

    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object p0

    invoke-interface {p0}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object p0

    const-string v0, "null cannot be cast to non-null type org.jetbrains.kotlin.descriptors.ClassDescriptor"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p0, Llyiahf/vczjk/by0;

    invoke-static {p0}, Llyiahf/vczjk/mba;->OooOO0O(Llyiahf/vczjk/by0;)Ljava/lang/Class;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    new-instance v0, Ljava/util/ArrayList;

    invoke-static {v2, v3}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v3

    invoke-direct {v0, v3}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_1

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/String;

    invoke-virtual {p0, v3, v1}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v3

    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_1
    return-object v0

    :cond_2
    return-object v1
.end method

.method public static final OooOO0O(Llyiahf/vczjk/dp8;)Ljava/util/ArrayList;
    .locals 7

    invoke-static {p0}, Llyiahf/vczjk/uz3;->OooO0oo(Llyiahf/vczjk/uk4;)Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_4

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object p0

    invoke-interface {p0}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object p0

    const-string v0, "null cannot be cast to non-null type org.jetbrains.kotlin.descriptors.ClassDescriptor"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p0, Llyiahf/vczjk/by0;

    sget v0, Llyiahf/vczjk/p72;->OooO00o:I

    invoke-interface {p0}, Llyiahf/vczjk/by0;->o0ooOOo()Llyiahf/vczjk/fca;

    move-result-object p0

    instance-of v0, p0, Llyiahf/vczjk/bq5;

    if-eqz v0, :cond_0

    move-object v1, p0

    check-cast v1, Llyiahf/vczjk/bq5;

    :cond_0
    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    new-instance p0, Ljava/util/ArrayList;

    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    iget-object v0, v1, Llyiahf/vczjk/bq5;->OooO00o:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_3

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/xn6;

    invoke-virtual {v1}, Llyiahf/vczjk/xn6;->OooO00o()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/qt5;

    invoke-virtual {v1}, Llyiahf/vczjk/xn6;->OooO0O0()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/dp8;

    invoke-static {v1}, Llyiahf/vczjk/qu6;->OooOO0O(Llyiahf/vczjk/dp8;)Ljava/util/ArrayList;

    move-result-object v1

    if-eqz v1, :cond_1

    new-instance v3, Ljava/util/ArrayList;

    const/16 v4, 0xa

    invoke-static {v1, v4}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v4

    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_2

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    new-instance v5, Ljava/lang/StringBuilder;

    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v2}, Llyiahf/vczjk/qt5;->OooO0OO()Ljava/lang/String;

    move-result-object v6

    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 v6, 0x2d

    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_1
    invoke-virtual {v2}, Llyiahf/vczjk/qt5;->OooO0OO()Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v3

    :cond_2
    invoke-static {v3, p0}, Llyiahf/vczjk/j21;->OoooOo0(Ljava/lang/Iterable;Ljava/util/Collection;)V

    goto :goto_0

    :cond_3
    return-object p0

    :cond_4
    return-object v1
.end method

.method public static final OooOO0o()Llyiahf/vczjk/qv3;
    .locals 19

    sget-object v0, Llyiahf/vczjk/qu6;->OooO0o0:Llyiahf/vczjk/qv3;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    new-instance v1, Llyiahf/vczjk/pv3;

    const/4 v9, 0x0

    const/4 v10, 0x0

    const-string v2, "Filled.SelectAll"

    const/high16 v3, 0x41c00000    # 24.0f

    const/high16 v4, 0x41c00000    # 24.0f

    const/high16 v5, 0x41c00000    # 24.0f

    const/high16 v6, 0x41c00000    # 24.0f

    const-wide/16 v7, 0x0

    const/16 v11, 0x60

    invoke-direct/range {v1 .. v11}, Llyiahf/vczjk/pv3;-><init>(Ljava/lang/String;FFFFJIZI)V

    sget v0, Llyiahf/vczjk/tda;->OooO00o:I

    new-instance v0, Llyiahf/vczjk/gx8;

    sget-wide v2, Llyiahf/vczjk/n21;->OooO0O0:J

    invoke-direct {v0, v2, v3}, Llyiahf/vczjk/gx8;-><init>(J)V

    new-instance v4, Llyiahf/vczjk/jq;

    const/4 v2, 0x1

    invoke-direct {v4, v2}, Llyiahf/vczjk/jq;-><init>(I)V

    const/high16 v2, 0x40400000    # 3.0f

    const/high16 v3, 0x40a00000    # 5.0f

    invoke-virtual {v4, v2, v3}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    const/high16 v11, 0x40000000    # 2.0f

    invoke-virtual {v4, v11}, Llyiahf/vczjk/jq;->OooO0o(F)V

    invoke-virtual {v4, v3, v2}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    const/high16 v7, -0x40000000    # -2.0f

    const v8, 0x3f666666    # 0.9f

    const v5, -0x40733333    # -1.1f

    const/4 v6, 0x0

    const/high16 v9, -0x40000000    # -2.0f

    const/high16 v10, 0x40000000    # 2.0f

    invoke-virtual/range {v4 .. v10}, Llyiahf/vczjk/jq;->OooO0Oo(FFFFFF)V

    invoke-virtual {v4}, Llyiahf/vczjk/jq;->OooO0O0()V

    const/high16 v12, 0x41500000    # 13.0f

    invoke-virtual {v4, v2, v12}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    invoke-virtual {v4, v11}, Llyiahf/vczjk/jq;->OooO0o(F)V

    const/high16 v13, -0x40000000    # -2.0f

    invoke-virtual {v4, v13}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    const/high16 v14, 0x41300000    # 11.0f

    invoke-virtual {v4, v2, v14}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    invoke-virtual {v4, v11}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    invoke-virtual {v4}, Llyiahf/vczjk/jq;->OooO0O0()V

    const/high16 v15, 0x40e00000    # 7.0f

    const/high16 v5, 0x41a80000    # 21.0f

    invoke-virtual {v4, v15, v5}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    invoke-virtual {v4, v11}, Llyiahf/vczjk/jq;->OooO0o(F)V

    invoke-virtual {v4, v13}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    const/high16 v6, 0x41980000    # 19.0f

    invoke-virtual {v4, v15, v6}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    invoke-virtual {v4, v11}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    invoke-virtual {v4}, Llyiahf/vczjk/jq;->OooO0O0()V

    const/high16 v7, 0x41100000    # 9.0f

    invoke-virtual {v4, v2, v7}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    invoke-virtual {v4, v11}, Llyiahf/vczjk/jq;->OooO0o(F)V

    invoke-virtual {v4, v3, v15}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    invoke-virtual {v4, v2, v15}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    invoke-virtual {v4, v11}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    invoke-virtual {v4}, Llyiahf/vczjk/jq;->OooO0O0()V

    invoke-virtual {v4, v12, v2}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    invoke-virtual {v4, v13}, Llyiahf/vczjk/jq;->OooO0o(F)V

    invoke-virtual {v4, v11}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    invoke-virtual {v4, v11}, Llyiahf/vczjk/jq;->OooO0o(F)V

    invoke-virtual {v4, v12, v2}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    invoke-virtual {v4}, Llyiahf/vczjk/jq;->OooO0O0()V

    invoke-virtual {v4, v6, v2}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    invoke-virtual {v4, v11}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    invoke-virtual {v4, v11}, Llyiahf/vczjk/jq;->OooO0o(F)V

    move v8, v7

    const v7, -0x4099999a    # -0.9f

    move v9, v8

    const/high16 v8, -0x40000000    # -2.0f

    move v10, v5

    const/4 v5, 0x0

    move/from16 v16, v6

    const v6, -0x40733333    # -1.1f

    move/from16 v17, v9

    const/high16 v9, -0x40000000    # -2.0f

    move/from16 v18, v10

    const/high16 v10, -0x40000000    # -2.0f

    move/from16 v14, v16

    move/from16 v15, v17

    move/from16 v12, v18

    invoke-virtual/range {v4 .. v10}, Llyiahf/vczjk/jq;->OooO0Oo(FFFFFF)V

    invoke-virtual {v4}, Llyiahf/vczjk/jq;->OooO0O0()V

    invoke-virtual {v4, v3, v12}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    invoke-virtual {v4, v13}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    invoke-virtual {v4, v2, v14}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    const v7, 0x3f666666    # 0.9f

    const/high16 v8, 0x40000000    # 2.0f

    const v6, 0x3f8ccccd    # 1.1f

    const/high16 v9, 0x40000000    # 2.0f

    const/high16 v10, 0x40000000    # 2.0f

    invoke-virtual/range {v4 .. v10}, Llyiahf/vczjk/jq;->OooO0Oo(FFFFFF)V

    invoke-virtual {v4}, Llyiahf/vczjk/jq;->OooO0O0()V

    const/high16 v5, 0x41880000    # 17.0f

    invoke-virtual {v4, v2, v5}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    invoke-virtual {v4, v11}, Llyiahf/vczjk/jq;->OooO0o(F)V

    invoke-virtual {v4, v13}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    const/high16 v6, 0x41700000    # 15.0f

    invoke-virtual {v4, v2, v6}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    invoke-virtual {v4, v11}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    invoke-virtual {v4}, Llyiahf/vczjk/jq;->OooO0O0()V

    invoke-virtual {v4, v15, v2}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    const/high16 v7, 0x40e00000    # 7.0f

    invoke-virtual {v4, v7, v2}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    invoke-virtual {v4, v11}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    invoke-virtual {v4, v11}, Llyiahf/vczjk/jq;->OooO0o(F)V

    invoke-virtual {v4, v15, v2}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    invoke-virtual {v4}, Llyiahf/vczjk/jq;->OooO0O0()V

    const/high16 v7, 0x41300000    # 11.0f

    invoke-virtual {v4, v7, v12}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    invoke-virtual {v4, v11}, Llyiahf/vczjk/jq;->OooO0o(F)V

    invoke-virtual {v4, v13}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    invoke-virtual {v4, v13}, Llyiahf/vczjk/jq;->OooO0o(F)V

    invoke-virtual {v4, v11}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    invoke-virtual {v4}, Llyiahf/vczjk/jq;->OooO0O0()V

    const/high16 v7, 0x41500000    # 13.0f

    invoke-virtual {v4, v14, v7}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    invoke-virtual {v4, v11}, Llyiahf/vczjk/jq;->OooO0o(F)V

    invoke-virtual {v4, v13}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    invoke-virtual {v4, v13}, Llyiahf/vczjk/jq;->OooO0o(F)V

    invoke-virtual {v4, v11}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    invoke-virtual {v4}, Llyiahf/vczjk/jq;->OooO0O0()V

    invoke-virtual {v4, v14, v12}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    const/high16 v7, 0x40000000    # 2.0f

    const v8, -0x4099999a    # -0.9f

    move v9, v5

    const v5, 0x3f8ccccd    # 1.1f

    move v10, v6

    const/4 v6, 0x0

    move/from16 v16, v9

    const/high16 v9, 0x40000000    # 2.0f

    move/from16 v18, v10

    const/high16 v10, -0x40000000    # -2.0f

    move/from16 v2, v16

    move/from16 v3, v18

    invoke-virtual/range {v4 .. v10}, Llyiahf/vczjk/jq;->OooO0Oo(FFFFFF)V

    invoke-virtual {v4, v13}, Llyiahf/vczjk/jq;->OooO0o(F)V

    invoke-virtual {v4, v11}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    invoke-virtual {v4}, Llyiahf/vczjk/jq;->OooO0O0()V

    invoke-virtual {v4, v14, v15}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    invoke-virtual {v4, v11}, Llyiahf/vczjk/jq;->OooO0o(F)V

    const/high16 v7, 0x40e00000    # 7.0f

    invoke-virtual {v4, v12, v7}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    invoke-virtual {v4, v13}, Llyiahf/vczjk/jq;->OooO0o(F)V

    invoke-virtual {v4, v11}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    invoke-virtual {v4}, Llyiahf/vczjk/jq;->OooO0O0()V

    invoke-virtual {v4, v14, v2}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    invoke-virtual {v4, v11}, Llyiahf/vczjk/jq;->OooO0o(F)V

    invoke-virtual {v4, v13}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    invoke-virtual {v4, v13}, Llyiahf/vczjk/jq;->OooO0o(F)V

    invoke-virtual {v4, v11}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    invoke-virtual {v4}, Llyiahf/vczjk/jq;->OooO0O0()V

    invoke-virtual {v4, v3, v12}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    invoke-virtual {v4, v11}, Llyiahf/vczjk/jq;->OooO0o(F)V

    invoke-virtual {v4, v13}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    invoke-virtual {v4, v13}, Llyiahf/vczjk/jq;->OooO0o(F)V

    invoke-virtual {v4, v11}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    invoke-virtual {v4}, Llyiahf/vczjk/jq;->OooO0O0()V

    const/high16 v5, 0x40a00000    # 5.0f

    invoke-virtual {v4, v3, v5}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    invoke-virtual {v4, v11}, Llyiahf/vczjk/jq;->OooO0o(F)V

    const/high16 v5, 0x40400000    # 3.0f

    invoke-virtual {v4, v2, v5}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    invoke-virtual {v4, v13}, Llyiahf/vczjk/jq;->OooO0o(F)V

    invoke-virtual {v4, v11}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    invoke-virtual {v4}, Llyiahf/vczjk/jq;->OooO0O0()V

    const/high16 v7, 0x40e00000    # 7.0f

    invoke-virtual {v4, v7, v2}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    const/high16 v5, 0x41200000    # 10.0f

    invoke-virtual {v4, v5}, Llyiahf/vczjk/jq;->OooO0o(F)V

    invoke-virtual {v4, v2, v7}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    invoke-virtual {v4, v7, v7}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    invoke-virtual {v4, v5}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    invoke-virtual {v4}, Llyiahf/vczjk/jq;->OooO0O0()V

    invoke-virtual {v4, v15, v15}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    const/high16 v2, 0x40c00000    # 6.0f

    invoke-virtual {v4, v2}, Llyiahf/vczjk/jq;->OooO0o(F)V

    invoke-virtual {v4, v2}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    invoke-virtual {v4, v15, v3}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    invoke-virtual {v4, v15, v15}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    invoke-virtual {v4}, Llyiahf/vczjk/jq;->OooO0O0()V

    iget-object v2, v4, Llyiahf/vczjk/jq;->OooO00o:Ljava/util/ArrayList;

    invoke-static {v1, v2, v0}, Llyiahf/vczjk/pv3;->OooO00o(Llyiahf/vczjk/pv3;Ljava/util/ArrayList;Llyiahf/vczjk/gx8;)V

    invoke-virtual {v1}, Llyiahf/vczjk/pv3;->OooO0O0()Llyiahf/vczjk/qv3;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/qu6;->OooO0o0:Llyiahf/vczjk/qv3;

    return-object v0
.end method

.method public static final OooOOO(Llyiahf/vczjk/iaa;Llyiahf/vczjk/uk4;)Llyiahf/vczjk/iaa;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "origin"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p1}, Llyiahf/vczjk/qu6;->OooO0oO(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/uk4;

    move-result-object p1

    invoke-static {p0, p1}, Llyiahf/vczjk/qu6;->OooOo0o(Llyiahf/vczjk/iaa;Llyiahf/vczjk/uk4;)Llyiahf/vczjk/iaa;

    move-result-object p0

    return-object p0
.end method

.method public static final OooOOO0()Llyiahf/vczjk/qv3;
    .locals 15

    sget-object v0, Llyiahf/vczjk/qu6;->OooO0o:Llyiahf/vczjk/qv3;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    new-instance v1, Llyiahf/vczjk/pv3;

    const/4 v9, 0x0

    const/4 v10, 0x0

    const-string v2, "Filled.Timer"

    const/high16 v3, 0x41c00000    # 24.0f

    const/high16 v4, 0x41c00000    # 24.0f

    const/high16 v5, 0x41c00000    # 24.0f

    const/high16 v6, 0x41c00000    # 24.0f

    const-wide/16 v7, 0x0

    const/16 v11, 0x60

    invoke-direct/range {v1 .. v11}, Llyiahf/vczjk/pv3;-><init>(Ljava/lang/String;FFFFJIZI)V

    sget v0, Llyiahf/vczjk/tda;->OooO00o:I

    new-instance v0, Llyiahf/vczjk/gx8;

    sget-wide v2, Llyiahf/vczjk/n21;->OooO0O0:J

    invoke-direct {v0, v2, v3}, Llyiahf/vczjk/gx8;-><init>(J)V

    new-instance v4, Ljava/util/ArrayList;

    const/16 v5, 0x20

    invoke-direct {v4, v5}, Ljava/util/ArrayList;-><init>(I)V

    new-instance v5, Llyiahf/vczjk/lq6;

    const/high16 v6, 0x3f800000    # 1.0f

    const/high16 v7, 0x41100000    # 9.0f

    invoke-direct {v5, v7, v6}, Llyiahf/vczjk/lq6;-><init>(FF)V

    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    new-instance v5, Llyiahf/vczjk/rq6;

    const/high16 v6, 0x40c00000    # 6.0f

    invoke-direct {v5, v6}, Llyiahf/vczjk/rq6;-><init>(F)V

    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    new-instance v5, Llyiahf/vczjk/xq6;

    const/high16 v6, 0x40000000    # 2.0f

    invoke-direct {v5, v6}, Llyiahf/vczjk/xq6;-><init>(F)V

    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    new-instance v5, Llyiahf/vczjk/rq6;

    const/high16 v8, -0x3f400000    # -6.0f

    invoke-direct {v5, v8}, Llyiahf/vczjk/rq6;-><init>(F)V

    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    sget-object v5, Llyiahf/vczjk/hq6;->OooO0OO:Llyiahf/vczjk/hq6;

    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    invoke-static {v1, v4, v0}, Llyiahf/vczjk/pv3;->OooO00o(Llyiahf/vczjk/pv3;Ljava/util/ArrayList;Llyiahf/vczjk/gx8;)V

    new-instance v0, Llyiahf/vczjk/gx8;

    invoke-direct {v0, v2, v3}, Llyiahf/vczjk/gx8;-><init>(J)V

    new-instance v8, Llyiahf/vczjk/jq;

    const/4 v2, 0x1

    invoke-direct {v8, v2}, Llyiahf/vczjk/jq;-><init>(I)V

    const v2, 0x41983d71    # 19.03f

    const v3, 0x40ec7ae1    # 7.39f

    invoke-virtual {v8, v2, v3}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    const v2, 0x3fb5c28f    # 1.42f

    const v3, -0x404a3d71    # -1.42f

    invoke-virtual {v8, v2, v3}, Llyiahf/vczjk/jq;->OooO0oo(FF)V

    const v11, -0x4099999a    # -0.9f

    const v12, -0x40828f5c    # -0.99f

    const v9, -0x4123d70a    # -0.43f

    const v10, -0x40fd70a4    # -0.51f

    const v13, -0x404b851f    # -1.41f

    const v14, -0x404b851f    # -1.41f

    invoke-virtual/range {v8 .. v14}, Llyiahf/vczjk/jq;->OooO0Oo(FFFFFF)V

    invoke-virtual {v8, v3, v2}, Llyiahf/vczjk/jq;->OooO0oo(FF)V

    const v11, 0x4161eb85    # 14.12f

    const/high16 v12, 0x40800000    # 4.0f

    const v9, 0x41808f5c    # 16.07f

    const v10, 0x4097ae14    # 4.74f

    const/high16 v13, 0x41400000    # 12.0f

    const/high16 v14, 0x40800000    # 4.0f

    invoke-virtual/range {v8 .. v14}, Llyiahf/vczjk/jq;->OooO0OO(FFFFFF)V

    const/high16 v11, -0x3ef00000    # -9.0f

    const v12, 0x4080f5c3    # 4.03f

    const v9, -0x3f60f5c3    # -4.97f

    const/4 v10, 0x0

    const/high16 v13, -0x3ef00000    # -9.0f

    const/high16 v14, 0x41100000    # 9.0f

    invoke-virtual/range {v8 .. v14}, Llyiahf/vczjk/jq;->OooO0Oo(FFFFFF)V

    const v11, 0x4080a3d7    # 4.02f

    const/high16 v12, 0x41100000    # 9.0f

    const/4 v9, 0x0

    const v10, 0x409f0a3d    # 4.97f

    const/high16 v13, 0x41100000    # 9.0f

    invoke-virtual/range {v8 .. v14}, Llyiahf/vczjk/jq;->OooO0Oo(FFFFFF)V

    const v2, -0x3f7f0a3d    # -4.03f

    const/high16 v3, -0x3ef00000    # -9.0f

    invoke-virtual {v8, v7, v2, v7, v3}, Llyiahf/vczjk/jq;->OooOO0o(FFFF)V

    const v11, 0x41a2147b    # 20.26f

    const v12, 0x410ee148    # 8.93f

    const/high16 v9, 0x41a80000    # 21.0f

    const v10, 0x412e147b    # 10.88f

    const v13, 0x41983d71    # 19.03f

    const v14, 0x40ec7ae1    # 7.39f

    invoke-virtual/range {v8 .. v14}, Llyiahf/vczjk/jq;->OooO0OO(FFFFFF)V

    invoke-virtual {v8}, Llyiahf/vczjk/jq;->OooO0O0()V

    const/high16 v2, 0x41500000    # 13.0f

    const/high16 v3, 0x41600000    # 14.0f

    invoke-virtual {v8, v2, v3}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    const/high16 v2, -0x40000000    # -2.0f

    invoke-virtual {v8, v2}, Llyiahf/vczjk/jq;->OooO0o(F)V

    const/high16 v2, 0x41000000    # 8.0f

    invoke-virtual {v8, v2}, Llyiahf/vczjk/jq;->OooOOO(F)V

    invoke-virtual {v8, v6}, Llyiahf/vczjk/jq;->OooO0o(F)V

    invoke-virtual {v8, v3}, Llyiahf/vczjk/jq;->OooOOO(F)V

    invoke-virtual {v8}, Llyiahf/vczjk/jq;->OooO0O0()V

    iget-object v2, v8, Llyiahf/vczjk/jq;->OooO00o:Ljava/util/ArrayList;

    invoke-static {v1, v2, v0}, Llyiahf/vczjk/pv3;->OooO00o(Llyiahf/vczjk/pv3;Ljava/util/ArrayList;Llyiahf/vczjk/gx8;)V

    invoke-virtual {v1}, Llyiahf/vczjk/pv3;->OooO0O0()Llyiahf/vczjk/qv3;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/qu6;->OooO0o:Llyiahf/vczjk/qv3;

    return-object v0
.end method

.method public static OooOOOO(Llyiahf/vczjk/gl9;Llyiahf/vczjk/yh9;Llyiahf/vczjk/mm9;Llyiahf/vczjk/xn4;Llyiahf/vczjk/yl9;ZLlyiahf/vczjk/s86;)V
    .locals 5

    if-nez p5, :cond_0

    goto/16 :goto_1

    :cond_0
    iget-wide v0, p0, Llyiahf/vczjk/gl9;->OooO0O0:J

    invoke-static {v0, v1}, Llyiahf/vczjk/gn9;->OooO0Oo(J)I

    move-result p0

    invoke-interface {p6, p0}, Llyiahf/vczjk/s86;->OooOO0(I)I

    move-result p0

    iget-object p5, p2, Llyiahf/vczjk/mm9;->OooO00o:Llyiahf/vczjk/lm9;

    iget-object p5, p5, Llyiahf/vczjk/lm9;->OooO00o:Llyiahf/vczjk/an;

    iget-object p5, p5, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    invoke-virtual {p5}, Ljava/lang/String;->length()I

    move-result p5

    const-wide v0, 0xffffffffL

    if-ge p0, p5, :cond_1

    invoke-virtual {p2, p0}, Llyiahf/vczjk/mm9;->OooO0O0(I)Llyiahf/vczjk/wj7;

    move-result-object p0

    goto :goto_0

    :cond_1
    if-eqz p0, :cond_2

    add-int/lit8 p0, p0, -0x1

    invoke-virtual {p2, p0}, Llyiahf/vczjk/mm9;->OooO0O0(I)Llyiahf/vczjk/wj7;

    move-result-object p0

    goto :goto_0

    :cond_2
    iget-object p0, p1, Llyiahf/vczjk/yh9;->OooO0oO:Llyiahf/vczjk/f62;

    iget-object p2, p1, Llyiahf/vczjk/yh9;->OooO0oo:Llyiahf/vczjk/aa3;

    iget-object p1, p1, Llyiahf/vczjk/yh9;->OooO0O0:Llyiahf/vczjk/rn9;

    invoke-static {p1, p0, p2}, Llyiahf/vczjk/oi9;->OooO0O0(Llyiahf/vczjk/rn9;Llyiahf/vczjk/f62;Llyiahf/vczjk/aa3;)J

    move-result-wide p0

    new-instance p2, Llyiahf/vczjk/wj7;

    and-long/2addr p0, v0

    long-to-int p0, p0

    int-to-float p0, p0

    const/4 p1, 0x0

    const/high16 p5, 0x3f800000    # 1.0f

    invoke-direct {p2, p1, p1, p5, p0}, Llyiahf/vczjk/wj7;-><init>(FFFF)V

    move-object p0, p2

    :goto_0
    iget p1, p0, Llyiahf/vczjk/wj7;->OooO00o:F

    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result p2

    int-to-long p5, p2

    iget p2, p0, Llyiahf/vczjk/wj7;->OooO0O0:F

    invoke-static {p2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v2

    int-to-long v2, v2

    const/16 v4, 0x20

    shl-long/2addr p5, v4

    and-long/2addr v2, v0

    or-long/2addr p5, v2

    invoke-interface {p3, p5, p6}, Llyiahf/vczjk/xn4;->OoooOO0(J)J

    move-result-wide p5

    shr-long v2, p5, v4

    long-to-int p3, v2

    invoke-static {p3}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p3

    and-long/2addr p5, v0

    long-to-int p5, p5

    invoke-static {p5}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p5

    invoke-static {p3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result p3

    int-to-long v2, p3

    invoke-static {p5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result p3

    int-to-long p5, p3

    shl-long/2addr v2, v4

    and-long/2addr p5, v0

    or-long/2addr p5, v2

    iget p3, p0, Llyiahf/vczjk/wj7;->OooO0OO:F

    sub-float/2addr p3, p1

    iget p0, p0, Llyiahf/vczjk/wj7;->OooO0Oo:F

    sub-float/2addr p0, p2

    invoke-static {p3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result p1

    int-to-long p1, p1

    invoke-static {p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result p0

    int-to-long v2, p0

    shl-long p0, p1, v4

    and-long p2, v2, v0

    or-long/2addr p0, p2

    invoke-static {p5, p6, p0, p1}, Llyiahf/vczjk/ll6;->OooO0O0(JJ)Llyiahf/vczjk/wj7;

    move-result-object p0

    iget-object p1, p4, Llyiahf/vczjk/yl9;->OooO00o:Llyiahf/vczjk/tl9;

    iget-object p1, p1, Llyiahf/vczjk/tl9;->OooO0O0:Ljava/util/concurrent/atomic/AtomicReference;

    invoke-virtual {p1}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/yl9;

    invoke-static {p1, p4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_3

    iget-object p1, p4, Llyiahf/vczjk/yl9;->OooO0O0:Llyiahf/vczjk/tx6;

    invoke-interface {p1, p0}, Llyiahf/vczjk/tx6;->OooO0o0(Llyiahf/vczjk/wj7;)V

    :cond_3
    :goto_1
    return-void
.end method

.method public static OooOOOo(Ljava/lang/Throwable;)V
    .locals 4

    sget-object v0, Llyiahf/vczjk/qu6;->OooO0Oo:Llyiahf/vczjk/nl1;

    if-nez p0, :cond_0

    new-instance p0, Ljava/lang/NullPointerException;

    const-string v1, "onError called with null. Null values are generally not allowed in 2.x operators and sources."

    invoke-direct {p0, v1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    goto :goto_0

    :cond_0
    instance-of v1, p0, Llyiahf/vczjk/ta6;

    if-eqz v1, :cond_1

    goto :goto_0

    :cond_1
    instance-of v1, p0, Ljava/lang/IllegalStateException;

    if-eqz v1, :cond_2

    goto :goto_0

    :cond_2
    instance-of v1, p0, Ljava/lang/NullPointerException;

    if-eqz v1, :cond_3

    goto :goto_0

    :cond_3
    instance-of v1, p0, Ljava/lang/IllegalArgumentException;

    if-eqz v1, :cond_4

    goto :goto_0

    :cond_4
    instance-of v1, p0, Llyiahf/vczjk/fg1;

    if-eqz v1, :cond_5

    goto :goto_0

    :cond_5
    new-instance v1, Llyiahf/vczjk/i8a;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "The exception could not be delivered to the consumer because it has already canceled/disposed the flow or the exception has nowhere to go to begin with. Further reading: https://github.com/ReactiveX/RxJava/wiki/What\'s-different-in-2.0#error-handling | "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-direct {v1, v2, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    move-object p0, v1

    :goto_0
    if-eqz v0, :cond_6

    :try_start_0
    invoke-interface {v0, p0}, Llyiahf/vczjk/nl1;->accept(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-void

    :catchall_0
    move-exception v0

    invoke-virtual {v0}, Ljava/lang/Throwable;->printStackTrace()V

    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Thread;->getUncaughtExceptionHandler()Ljava/lang/Thread$UncaughtExceptionHandler;

    move-result-object v2

    invoke-interface {v2, v1, v0}, Ljava/lang/Thread$UncaughtExceptionHandler;->uncaughtException(Ljava/lang/Thread;Ljava/lang/Throwable;)V

    :cond_6
    invoke-virtual {p0}, Ljava/lang/Throwable;->printStackTrace()V

    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Thread;->getUncaughtExceptionHandler()Ljava/lang/Thread$UncaughtExceptionHandler;

    move-result-object v1

    invoke-interface {v1, v0, p0}, Ljava/lang/Thread$UncaughtExceptionHandler;->uncaughtException(Ljava/lang/Thread;Ljava/lang/Throwable;)V

    return-void
.end method

.method public static final OooOOo(Llyiahf/vczjk/ky4;Llyiahf/vczjk/jy4;Llyiahf/vczjk/ze3;Llyiahf/vczjk/eb9;)Ljava/lang/Object;
    .locals 3

    sget-object v0, Llyiahf/vczjk/jy4;->OooOOO:Llyiahf/vczjk/jy4;

    if-eq p1, v0, :cond_2

    invoke-virtual {p0}, Llyiahf/vczjk/ky4;->OooO0O0()Llyiahf/vczjk/jy4;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/jy4;->OooOOO0:Llyiahf/vczjk/jy4;

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    if-ne v0, v1, :cond_0

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/lq7;

    const/4 v1, 0x0

    invoke-direct {v0, p0, p1, p2, v1}, Llyiahf/vczjk/lq7;-><init>(Llyiahf/vczjk/ky4;Llyiahf/vczjk/jy4;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V

    invoke-static {v0, p3}, Llyiahf/vczjk/v34;->Oooo00O(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p0

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p0, p1, :cond_1

    return-object p0

    :cond_1
    :goto_0
    return-object v2

    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "repeatOnLifecycle cannot start work with the INITIALIZED lifecycle state."

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static final OooOOo0(FLlyiahf/vczjk/jr1;Ljava/util/List;)Llyiahf/vczjk/aw7;
    .locals 7

    const-string v0, "rounding"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x2

    int-to-float v1, v0

    div-float/2addr p0, v1

    const/4 v2, 0x0

    sub-float v3, v2, p0

    const/high16 v4, 0x3f800000    # 1.0f

    div-float/2addr v4, v1

    sub-float v1, v2, v4

    add-float/2addr p0, v2

    add-float/2addr v4, v2

    const/16 v5, 0x8

    new-array v5, v5, [F

    const/4 v6, 0x0

    aput p0, v5, v6

    const/4 v6, 0x1

    aput v4, v5, v6

    aput v3, v5, v0

    const/4 v0, 0x3

    aput v4, v5, v0

    const/4 v0, 0x4

    aput v3, v5, v0

    const/4 v0, 0x5

    aput v1, v5, v0

    const/4 v0, 0x6

    aput p0, v5, v0

    const/4 p0, 0x7

    aput v1, v5, p0

    invoke-static {v5, p1, p2, v2, v2}, Llyiahf/vczjk/er8;->OooO0o0([FLlyiahf/vczjk/jr1;Ljava/util/List;FF)Llyiahf/vczjk/aw7;

    move-result-object p0

    return-object p0
.end method

.method public static final OooOOoo(IFLlyiahf/vczjk/jr1;)Llyiahf/vczjk/aw7;
    .locals 2

    const-string v0, "rounding"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/16 v0, 0xf0

    const/4 v1, 0x0

    invoke-static {p0, p1, p2, v1, v0}, Llyiahf/vczjk/qu6;->OooOo00(IFLlyiahf/vczjk/jr1;Llyiahf/vczjk/jr1;I)Llyiahf/vczjk/aw7;

    move-result-object p0

    return-object p0
.end method

.method public static final OooOo0(Llyiahf/vczjk/v02;)Ljava/lang/Class;
    .locals 4

    instance-of v0, p0, Llyiahf/vczjk/by0;

    if-eqz v0, :cond_1

    invoke-static {p0}, Llyiahf/vczjk/uz3;->OooO0O0(Llyiahf/vczjk/v02;)Z

    move-result v0

    if-eqz v0, :cond_1

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/by0;

    invoke-static {v0}, Llyiahf/vczjk/mba;->OooOO0O(Llyiahf/vczjk/by0;)Ljava/lang/Class;

    move-result-object v1

    if-eqz v1, :cond_0

    return-object v1

    :cond_0
    new-instance v1, Llyiahf/vczjk/es1;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Class object for the class "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-interface {v0}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v0

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v0, " cannot be found (classId="

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    check-cast p0, Llyiahf/vczjk/gz0;

    invoke-static {p0}, Llyiahf/vczjk/p72;->OooO0o(Llyiahf/vczjk/gz0;)Llyiahf/vczjk/hy0;

    move-result-object p0

    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 p0, 0x29

    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {v1, p0}, Llyiahf/vczjk/es1;-><init>(Ljava/lang/String;)V

    throw v1

    :cond_1
    const/4 p0, 0x0

    return-object p0
.end method

.method public static OooOo00(IFLlyiahf/vczjk/jr1;Llyiahf/vczjk/jr1;I)Llyiahf/vczjk/aw7;
    .locals 9

    and-int/lit8 p4, p4, 0x10

    const/4 v0, 0x0

    if-eqz p4, :cond_0

    move-object p3, v0

    :cond_0
    const-string p4, "rounding"

    invoke-static {p2, p4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 p4, 0x0

    cmpg-float v1, p1, p4

    if-lez v1, :cond_5

    const/high16 v1, 0x3f800000    # 1.0f

    cmpl-float v2, p1, v1

    if-gez v2, :cond_4

    const/4 v2, 0x0

    if-eqz p3, :cond_2

    invoke-static {v2, p0}, Llyiahf/vczjk/vt6;->Oooo0oO(II)Llyiahf/vczjk/x14;

    move-result-object v0

    new-instance v3, Ljava/util/ArrayList;

    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {v0}, Llyiahf/vczjk/v14;->OooO00o()Llyiahf/vczjk/w14;

    move-result-object v0

    :goto_0
    iget-boolean v4, v0, Llyiahf/vczjk/w14;->OooOOOO:Z

    if-eqz v4, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/n14;->OooO00o()I

    filled-new-array {p2, p3}, [Llyiahf/vczjk/jr1;

    move-result-object v4

    invoke-static {v4}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v4

    invoke-static {v4, v3}, Llyiahf/vczjk/j21;->OoooOo0(Ljava/lang/Iterable;Ljava/util/Collection;)V

    goto :goto_0

    :cond_1
    move-object v0, v3

    :cond_2
    mul-int/lit8 p3, p0, 0x4

    new-array p3, p3, [F

    move v3, v2

    :goto_1
    if-ge v2, p0, :cond_3

    sget v4, Llyiahf/vczjk/tba;->OooO0O0:F

    int-to-float v5, p0

    div-float/2addr v4, v5

    const/4 v5, 0x2

    int-to-float v5, v5

    mul-float/2addr v5, v4

    int-to-float v6, v2

    mul-float/2addr v5, v6

    invoke-static {v1, v5}, Llyiahf/vczjk/tba;->OooO0o0(FF)J

    move-result-wide v5

    add-int/lit8 v7, v3, 0x1

    invoke-static {v5, v6}, Llyiahf/vczjk/rl6;->OooOOo(J)F

    move-result v8

    add-float/2addr v8, p4

    aput v8, p3, v3

    add-int/lit8 v8, v3, 0x2

    invoke-static {v5, v6}, Llyiahf/vczjk/rl6;->OooOOoo(J)F

    move-result v5

    add-float/2addr v5, p4

    aput v5, p3, v7

    mul-int/lit8 v5, v2, 0x2

    add-int/lit8 v5, v5, 0x1

    int-to-float v5, v5

    mul-float/2addr v4, v5

    invoke-static {p1, v4}, Llyiahf/vczjk/tba;->OooO0o0(FF)J

    move-result-wide v4

    add-int/lit8 v6, v3, 0x3

    invoke-static {v4, v5}, Llyiahf/vczjk/rl6;->OooOOo(J)F

    move-result v7

    add-float/2addr v7, p4

    aput v7, p3, v8

    add-int/lit8 v3, v3, 0x4

    invoke-static {v4, v5}, Llyiahf/vczjk/rl6;->OooOOoo(J)F

    move-result v4

    add-float/2addr v4, p4

    aput v4, p3, v6

    add-int/lit8 v2, v2, 0x1

    goto :goto_1

    :cond_3
    invoke-static {p3, p2, v0, p4, p4}, Llyiahf/vczjk/er8;->OooO0o0([FLlyiahf/vczjk/jr1;Ljava/util/List;FF)Llyiahf/vczjk/aw7;

    move-result-object p0

    return-object p0

    :cond_4
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "innerRadius must be less than radius"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_5
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "Star radii must both be greater than 0"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static final OooOo0O(Llyiahf/vczjk/uk4;)Ljava/lang/Class;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/qu6;->OooOo0(Llyiahf/vczjk/v02;)Ljava/lang/Class;

    move-result-object v0

    if-nez v0, :cond_0

    goto :goto_1

    :cond_0
    invoke-static {p0}, Llyiahf/vczjk/l5a;->OooO0o0(Llyiahf/vczjk/uk4;)Z

    move-result v1

    if-nez v1, :cond_1

    goto :goto_0

    :cond_1
    invoke-static {p0}, Llyiahf/vczjk/uz3;->OooO(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/dp8;

    move-result-object p0

    if-nez p0, :cond_2

    goto :goto_1

    :cond_2
    invoke-static {p0}, Llyiahf/vczjk/l5a;->OooO0o0(Llyiahf/vczjk/uk4;)Z

    move-result v1

    if-nez v1, :cond_3

    invoke-static {p0}, Llyiahf/vczjk/hk4;->Oooo00O(Llyiahf/vczjk/uk4;)Z

    move-result p0

    if-nez p0, :cond_3

    :goto_0
    return-object v0

    :cond_3
    :goto_1
    const/4 p0, 0x0

    return-object p0
.end method

.method public static final OooOo0o(Llyiahf/vczjk/iaa;Llyiahf/vczjk/uk4;)Llyiahf/vczjk/iaa;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v0, p0, Llyiahf/vczjk/p5a;

    if-eqz v0, :cond_0

    check-cast p0, Llyiahf/vczjk/p5a;

    invoke-interface {p0}, Llyiahf/vczjk/p5a;->OoooOOo()Llyiahf/vczjk/iaa;

    move-result-object p0

    invoke-static {p0, p1}, Llyiahf/vczjk/qu6;->OooOo0o(Llyiahf/vczjk/iaa;Llyiahf/vczjk/uk4;)Llyiahf/vczjk/iaa;

    move-result-object p0

    return-object p0

    :cond_0
    if-eqz p1, :cond_4

    invoke-virtual {p1, p0}, Llyiahf/vczjk/uk4;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_1

    goto :goto_0

    :cond_1
    instance-of v0, p0, Llyiahf/vczjk/dp8;

    if-eqz v0, :cond_2

    new-instance v0, Llyiahf/vczjk/ip8;

    check-cast p0, Llyiahf/vczjk/dp8;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/ip8;-><init>(Llyiahf/vczjk/dp8;Llyiahf/vczjk/uk4;)V

    return-object v0

    :cond_2
    instance-of v0, p0, Llyiahf/vczjk/k23;

    if-eqz v0, :cond_3

    new-instance v0, Llyiahf/vczjk/n23;

    check-cast p0, Llyiahf/vczjk/k23;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/n23;-><init>(Llyiahf/vczjk/k23;Llyiahf/vczjk/uk4;)V

    return-object v0

    :cond_3
    new-instance p0, Llyiahf/vczjk/k61;

    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    throw p0

    :cond_4
    :goto_0
    return-object p0
.end method
