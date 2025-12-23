.class public final Llyiahf/vczjk/ih4;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/kh4;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/kh4;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/ih4;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/ih4;->OooOOO:Llyiahf/vczjk/kh4;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 8

    iget v0, p0, Llyiahf/vczjk/ih4;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/ih4;->OooOOO:Llyiahf/vczjk/kh4;

    invoke-virtual {v0}, Llyiahf/vczjk/ai4;->OooOOoo()Ljava/lang/reflect/Member;

    move-result-object v1

    const-string v2, "delegate field/method "

    const-string v3, "delegate method "

    :try_start_0
    sget-object v4, Llyiahf/vczjk/ai4;->OooOo0:Ljava/lang/Object;

    invoke-virtual {v0}, Llyiahf/vczjk/ai4;->OooOOo0()Z

    move-result v5

    const/4 v6, 0x0

    if-eqz v5, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/ai4;->OooOo00()Llyiahf/vczjk/sa7;

    move-result-object v5

    iget-object v7, v0, Llyiahf/vczjk/ai4;->OooOOo:Ljava/lang/Object;

    invoke-static {v7, v5}, Llyiahf/vczjk/qu6;->OooO0o0(Ljava/lang/Object;Llyiahf/vczjk/eo0;)Ljava/lang/Object;

    move-result-object v5

    goto :goto_0

    :cond_0
    move-object v5, v6

    :goto_0
    if-eq v5, v4, :cond_1

    goto :goto_1

    :cond_1
    move-object v5, v6

    :goto_1
    if-eqz v1, :cond_2

    move-object v4, v1

    check-cast v4, Ljava/lang/reflect/AccessibleObject;

    goto :goto_2

    :catch_0
    move-exception v0

    goto/16 :goto_4

    :cond_2
    move-object v4, v6

    :goto_2
    if-eqz v4, :cond_3

    invoke-static {v0}, Llyiahf/vczjk/u34;->Oooo00O(Llyiahf/vczjk/bf4;)Z

    move-result v0

    invoke-virtual {v4, v0}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    :cond_3
    if-nez v1, :cond_4

    goto/16 :goto_3

    :cond_4
    instance-of v0, v1, Ljava/lang/reflect/Field;

    if-eqz v0, :cond_5

    check-cast v1, Ljava/lang/reflect/Field;

    invoke-virtual {v1, v5}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v6

    goto :goto_3

    :cond_5
    instance-of v0, v1, Ljava/lang/reflect/Method;

    if-eqz v0, :cond_a

    move-object v0, v1

    check-cast v0, Ljava/lang/reflect/Method;

    invoke-virtual {v0}, Ljava/lang/reflect/Method;->getParameterTypes()[Ljava/lang/Class;

    move-result-object v0

    array-length v0, v0
    :try_end_0
    .catch Ljava/lang/IllegalAccessException; {:try_start_0 .. :try_end_0} :catch_0

    if-eqz v0, :cond_9

    const-string v2, "get(...)"

    const/4 v4, 0x1

    if-eq v0, v4, :cond_7

    const/4 v7, 0x2

    if-ne v0, v7, :cond_6

    :try_start_1
    move-object v0, v1

    check-cast v0, Ljava/lang/reflect/Method;

    check-cast v1, Ljava/lang/reflect/Method;

    invoke-virtual {v1}, Ljava/lang/reflect/Method;->getParameterTypes()[Ljava/lang/Class;

    move-result-object v1

    aget-object v1, v1, v4

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v1}, Llyiahf/vczjk/mba;->OooO0o0(Ljava/lang/reflect/Type;)Ljava/lang/Object;

    move-result-object v1

    filled-new-array {v5, v1}, [Ljava/lang/Object;

    move-result-object v1

    invoke-virtual {v0, v6, v1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v6

    goto :goto_3

    :cond_6
    new-instance v0, Ljava/lang/AssertionError;

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, " should take 0, 1, or 2 parameters"

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    throw v0

    :cond_7
    move-object v0, v1

    check-cast v0, Ljava/lang/reflect/Method;

    if-nez v5, :cond_8

    check-cast v1, Ljava/lang/reflect/Method;

    invoke-virtual {v1}, Ljava/lang/reflect/Method;->getParameterTypes()[Ljava/lang/Class;

    move-result-object v1

    const/4 v3, 0x0

    aget-object v1, v1, v3

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v1}, Llyiahf/vczjk/mba;->OooO0o0(Ljava/lang/reflect/Type;)Ljava/lang/Object;

    move-result-object v5

    :cond_8
    filled-new-array {v5}, [Ljava/lang/Object;

    move-result-object v1

    invoke-virtual {v0, v6, v1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v6

    goto :goto_3

    :cond_9
    check-cast v1, Ljava/lang/reflect/Method;

    invoke-virtual {v1, v6, v6}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v6

    :goto_3
    return-object v6

    :cond_a
    new-instance v0, Ljava/lang/AssertionError;

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, " neither field nor method"

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    throw v0
    :try_end_1
    .catch Ljava/lang/IllegalAccessException; {:try_start_1 .. :try_end_1} :catch_0

    :goto_4
    new-instance v1, Llyiahf/vczjk/hu3;

    const-string v2, "Cannot obtain the delegate of a non-accessible property. Use \"isAccessible = true\" to make the property accessible"

    invoke-direct {v1, v2, v0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    throw v1

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/jh4;

    iget-object v1, p0, Llyiahf/vczjk/ih4;->OooOOO:Llyiahf/vczjk/kh4;

    invoke-direct {v0, v1}, Llyiahf/vczjk/jh4;-><init>(Llyiahf/vczjk/kh4;)V

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
