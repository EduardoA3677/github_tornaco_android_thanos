.class public abstract Llyiahf/vczjk/ag8;
.super Llyiahf/vczjk/bg8;


# direct methods
.method public static Oooo(Llyiahf/vczjk/wf8;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/e13;
    .locals 2

    new-instance v0, Llyiahf/vczjk/jy9;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/jy9;-><init>(Llyiahf/vczjk/wf8;Llyiahf/vczjk/oe3;)V

    new-instance p0, Llyiahf/vczjk/r07;

    const/16 p1, 0x17

    invoke-direct {p0, p1}, Llyiahf/vczjk/r07;-><init>(I)V

    new-instance p1, Llyiahf/vczjk/e13;

    const/4 v1, 0x0

    invoke-direct {p1, v0, v1, p0}, Llyiahf/vczjk/e13;-><init>(Llyiahf/vczjk/wf8;ZLlyiahf/vczjk/oe3;)V

    return-object p1
.end method

.method public static Oooo0(Llyiahf/vczjk/wf8;I)Llyiahf/vczjk/wf8;
    .locals 1

    if-ltz p1, :cond_2

    if-nez p1, :cond_0

    return-object p0

    :cond_0
    instance-of v0, p0, Llyiahf/vczjk/fj2;

    if-eqz v0, :cond_1

    check-cast p0, Llyiahf/vczjk/fj2;

    invoke-interface {p0, p1}, Llyiahf/vczjk/fj2;->OooO00o(I)Llyiahf/vczjk/wf8;

    move-result-object p0

    return-object p0

    :cond_1
    new-instance v0, Llyiahf/vczjk/aj2;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/aj2;-><init>(Llyiahf/vczjk/wf8;I)V

    return-object v0

    :cond_2
    const-string p0, "Requested element count "

    const-string v0, " is less than zero."

    invoke-static {p1, p0, v0}, Llyiahf/vczjk/ii5;->OooO0o(ILjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    new-instance p1, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public static Oooo00O(Ljava/util/Iterator;)Llyiahf/vczjk/wf8;
    .locals 2

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/vy;

    const/4 v1, 0x4

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/vy;-><init>(Ljava/lang/Object;I)V

    new-instance p0, Llyiahf/vczjk/mj1;

    invoke-direct {p0, v0}, Llyiahf/vczjk/mj1;-><init>(Llyiahf/vczjk/wf8;)V

    return-object p0
.end method

.method public static Oooo00o(Llyiahf/vczjk/wf8;)I
    .locals 2

    invoke-interface {p0}, Llyiahf/vczjk/wf8;->iterator()Ljava/util/Iterator;

    move-result-object p0

    const/4 v0, 0x0

    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    add-int/lit8 v0, v0, 0x1

    if-ltz v0, :cond_0

    goto :goto_0

    :cond_0
    new-instance p0, Ljava/lang/ArithmeticException;

    const-string v0, "Count overflow has happened."

    invoke-direct {p0, v0}, Ljava/lang/ArithmeticException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_1
    return v0
.end method

.method public static final Oooo0O0(Llyiahf/vczjk/wf8;)Llyiahf/vczjk/oz2;
    .locals 4

    new-instance v0, Llyiahf/vczjk/r07;

    const/16 v1, 0x15

    invoke-direct {v0, v1}, Llyiahf/vczjk/r07;-><init>(I)V

    instance-of v1, p0, Llyiahf/vczjk/jy9;

    if-eqz v1, :cond_0

    check-cast p0, Llyiahf/vczjk/jy9;

    new-instance v1, Llyiahf/vczjk/oz2;

    iget-object v2, p0, Llyiahf/vczjk/jy9;->OooO00o:Llyiahf/vczjk/wf8;

    iget-object p0, p0, Llyiahf/vczjk/jy9;->OooO0O0:Llyiahf/vczjk/oe3;

    invoke-direct {v1, v2, p0, v0}, Llyiahf/vczjk/oz2;-><init>(Llyiahf/vczjk/wf8;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)V

    return-object v1

    :cond_0
    new-instance v1, Llyiahf/vczjk/oz2;

    new-instance v2, Llyiahf/vczjk/r07;

    const/16 v3, 0x16

    invoke-direct {v2, v3}, Llyiahf/vczjk/r07;-><init>(I)V

    invoke-direct {v1, p0, v2, v0}, Llyiahf/vczjk/oz2;-><init>(Llyiahf/vczjk/wf8;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)V

    return-object v1
.end method

.method public static Oooo0OO(Ljava/lang/Object;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/wf8;
    .locals 3

    if-nez p0, :cond_0

    sget-object p0, Llyiahf/vczjk/fn2;->OooO00o:Llyiahf/vczjk/fn2;

    return-object p0

    :cond_0
    new-instance v0, Llyiahf/vczjk/b62;

    new-instance v1, Llyiahf/vczjk/ku7;

    const/4 v2, 0x5

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/ku7;-><init>(Ljava/lang/Object;I)V

    const/4 p0, 0x1

    invoke-direct {v0, p0, v1, p1}, Llyiahf/vczjk/b62;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    return-object v0
.end method

.method public static Oooo0o(Llyiahf/vczjk/wf8;Ljava/lang/String;)Ljava/lang/String;
    .locals 5

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, ""

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    invoke-interface {p0}, Llyiahf/vczjk/wf8;->iterator()Ljava/util/Iterator;

    move-result-object p0

    const/4 v2, 0x0

    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_1

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    const/4 v4, 0x1

    add-int/2addr v2, v4

    if-le v2, v4, :cond_0

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    :cond_0
    const/4 v4, 0x0

    invoke-static {v0, v3, v4}, Llyiahf/vczjk/qu6;->OooO0O0(Ljava/lang/StringBuilder;Ljava/lang/Object;Llyiahf/vczjk/oe3;)V

    goto :goto_0

    :cond_1
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static Oooo0o0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/wf8;
    .locals 3

    new-instance v0, Llyiahf/vczjk/b62;

    new-instance v1, Llyiahf/vczjk/hp;

    const/16 v2, 0x8

    invoke-direct {v1, v2, p0}, Llyiahf/vczjk/hp;-><init>(ILlyiahf/vczjk/le3;)V

    const/4 v2, 0x1

    invoke-direct {v0, v2, p0, v1}, Llyiahf/vczjk/b62;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    new-instance p0, Llyiahf/vczjk/mj1;

    invoke-direct {p0, v0}, Llyiahf/vczjk/mj1;-><init>(Llyiahf/vczjk/wf8;)V

    return-object p0
.end method

.method public static Oooo0oO(Llyiahf/vczjk/wf8;)Ljava/lang/Object;
    .locals 2

    invoke-interface {p0}, Llyiahf/vczjk/wf8;->iterator()Ljava/util/Iterator;

    move-result-object p0

    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    goto :goto_0

    :cond_0
    return-object v0

    :cond_1
    new-instance p0, Ljava/util/NoSuchElementException;

    const-string v0, "Sequence is empty."

    invoke-direct {p0, v0}, Ljava/util/NoSuchElementException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static Oooo0oo(Llyiahf/vczjk/wf8;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/jy9;
    .locals 1

    const-string v0, "transform"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/jy9;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/jy9;-><init>(Llyiahf/vczjk/wf8;Llyiahf/vczjk/oe3;)V

    return-object v0
.end method

.method public static OoooO00(Llyiahf/vczjk/wf8;)Ljava/util/List;
    .locals 2

    invoke-interface {p0}, Llyiahf/vczjk/wf8;->iterator()Ljava/util/Iterator;

    move-result-object p0

    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-nez v0, :cond_0

    sget-object p0, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    return-object p0

    :cond_0
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-nez v1, :cond_1

    invoke-static {v0}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object p0

    return-object p0

    :cond_1
    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_2
    return-object v1
.end method
