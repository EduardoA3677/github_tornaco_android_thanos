.class public final synthetic Llyiahf/vczjk/yz2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Lorg/apache/commons/io/function/IOFunction;
.implements Lorg/apache/commons/io/function/IOPredicate;
.implements Lorg/apache/commons/io/function/IOUnaryOperator;
.implements Lorg/apache/commons/io/function/IOSupplier;
.implements Llyiahf/vczjk/sj8;
.implements Llyiahf/vczjk/o0oo0000;
.implements Llyiahf/vczjk/n59;
.implements Llyiahf/vczjk/sd2;
.implements Lorg/apache/commons/codec/language/bm/Rule$RPattern;
.implements Llyiahf/vczjk/md8;
.implements Llyiahf/vczjk/nl1;
.implements Lgithub/tornaco/android/thanos/core/util/function/Function;


# instance fields
.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/yz2;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public OooO00o(Llyiahf/vczjk/kr1;)Llyiahf/vczjk/kr1;
    .locals 1

    sget v0, Lcom/google/android/material/carousel/MaskableFrameLayout;->OooOo0:I

    instance-of v0, p1, Llyiahf/vczjk/o00Ooo;

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/o00Ooo;

    new-instance v0, Llyiahf/vczjk/sx0;

    iget p1, p1, Llyiahf/vczjk/o00Ooo;->OooO00o:F

    invoke-direct {v0, p1}, Llyiahf/vczjk/sx0;-><init>(F)V

    return-object v0

    :cond_0
    return-object p1
.end method

.method public OooO0OO(Landroid/view/View;Llyiahf/vczjk/m59;)V
    .locals 1

    sget v0, Lgithub/tornaco/thanos/android/ops/ops/remind/RemindOpsActivity;->Oooo:I

    sget-object v0, Llyiahf/vczjk/m59;->OooOOO:Llyiahf/vczjk/m59;

    if-ne p2, v0, :cond_0

    const/high16 p2, 0x41000000    # 8.0f

    goto :goto_0

    :cond_0
    const/4 p2, 0x0

    :goto_0
    invoke-virtual {p1, p2}, Landroid/view/View;->setElevation(F)V

    return-void
.end method

.method public OooO0o(Llyiahf/vczjk/hl1;)Llyiahf/vczjk/ld8;
    .locals 10

    iget v0, p0, Llyiahf/vczjk/yz2;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p1, Llyiahf/vczjk/hl1;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ld8;

    if-nez v0, :cond_0

    sget-object v0, Llyiahf/vczjk/wp3;->OooOo00:Llyiahf/vczjk/wp3;

    invoke-static {p1, v0}, Llyiahf/vczjk/ru6;->OooO0oo(Llyiahf/vczjk/hl1;Llyiahf/vczjk/sg0;)Llyiahf/vczjk/ld8;

    move-result-object v0

    goto/16 :goto_8

    :cond_0
    iget-object v1, p1, Llyiahf/vczjk/hl1;->OooOOOo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/id8;

    iget-boolean v2, p1, Llyiahf/vczjk/hl1;->OooOOO:Z

    iget-object v3, v0, Llyiahf/vczjk/ld8;->OooO0O0:Llyiahf/vczjk/kd8;

    iget-object v4, v0, Llyiahf/vczjk/ld8;->OooO00o:Llyiahf/vczjk/kd8;

    if-eqz v2, :cond_1

    invoke-static {p1, v1, v4}, Llyiahf/vczjk/ru6;->OooOO0(Llyiahf/vczjk/hl1;Llyiahf/vczjk/id8;Llyiahf/vczjk/kd8;)Llyiahf/vczjk/kd8;

    move-result-object v1

    move-object v2, v3

    move-object v3, v4

    move-object v4, v1

    goto :goto_0

    :cond_1
    invoke-static {p1, v1, v3}, Llyiahf/vczjk/ru6;->OooOO0(Llyiahf/vczjk/hl1;Llyiahf/vczjk/id8;Llyiahf/vczjk/kd8;)Llyiahf/vczjk/kd8;

    move-result-object v1

    move-object v2, v1

    :goto_0
    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_2

    goto/16 :goto_8

    :cond_2
    invoke-virtual {p1}, Llyiahf/vczjk/hl1;->OooO0o()Llyiahf/vczjk/vs1;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/vs1;->OooOOO0:Llyiahf/vczjk/vs1;

    if-eq v0, v1, :cond_4

    invoke-virtual {p1}, Llyiahf/vczjk/hl1;->OooO0o()Llyiahf/vczjk/vs1;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/vs1;->OooOOOO:Llyiahf/vczjk/vs1;

    if-ne v0, v1, :cond_3

    iget v0, v4, Llyiahf/vczjk/kd8;->OooO0O0:I

    iget v1, v2, Llyiahf/vczjk/kd8;->OooO0O0:I

    if-le v0, v1, :cond_3

    goto :goto_1

    :cond_3
    const/4 v0, 0x0

    goto :goto_2

    :cond_4
    :goto_1
    const/4 v0, 0x1

    :goto_2
    new-instance v1, Llyiahf/vczjk/ld8;

    invoke-direct {v1, v4, v2, v0}, Llyiahf/vczjk/ld8;-><init>(Llyiahf/vczjk/kd8;Llyiahf/vczjk/kd8;Z)V

    iget-object v0, p1, Llyiahf/vczjk/hl1;->OooOOOo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/id8;

    iget-object v2, v1, Llyiahf/vczjk/ld8;->OooO00o:Llyiahf/vczjk/kd8;

    iget-wide v3, v2, Llyiahf/vczjk/kd8;->OooO0OO:J

    iget-object v5, v1, Llyiahf/vczjk/ld8;->OooO0O0:Llyiahf/vczjk/kd8;

    iget-wide v6, v5, Llyiahf/vczjk/kd8;->OooO0OO:J

    cmp-long v3, v3, v6

    if-nez v3, :cond_5

    iget v2, v2, Llyiahf/vczjk/kd8;->OooO0O0:I

    iget v3, v5, Llyiahf/vczjk/kd8;->OooO0O0:I

    if-ne v2, v3, :cond_12

    goto :goto_4

    :cond_5
    iget-boolean v3, v1, Llyiahf/vczjk/ld8;->OooO0OO:Z

    if-eqz v3, :cond_6

    move-object v4, v2

    goto :goto_3

    :cond_6
    move-object v4, v5

    :goto_3
    iget v4, v4, Llyiahf/vczjk/kd8;->OooO0O0:I

    if-eqz v4, :cond_7

    goto/16 :goto_7

    :cond_7
    if-eqz v3, :cond_8

    move-object v2, v5

    :cond_8
    iget-object v3, v0, Llyiahf/vczjk/id8;->OooO0Oo:Llyiahf/vczjk/mm9;

    iget-object v3, v3, Llyiahf/vczjk/mm9;->OooO00o:Llyiahf/vczjk/lm9;

    iget-object v3, v3, Llyiahf/vczjk/lm9;->OooO00o:Llyiahf/vczjk/an;

    iget-object v3, v3, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    invoke-virtual {v3}, Ljava/lang/String;->length()I

    move-result v3

    iget v2, v2, Llyiahf/vczjk/kd8;->OooO0O0:I

    if-eq v3, v2, :cond_9

    goto/16 :goto_7

    :cond_9
    :goto_4
    iget-object v2, v0, Llyiahf/vczjk/id8;->OooO0Oo:Llyiahf/vczjk/mm9;

    iget-object v2, v2, Llyiahf/vczjk/mm9;->OooO00o:Llyiahf/vczjk/lm9;

    iget-object v2, v2, Llyiahf/vczjk/lm9;->OooO00o:Llyiahf/vczjk/an;

    iget-object v2, v2, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    iget-object v3, p1, Llyiahf/vczjk/hl1;->OooOOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/ld8;

    if-eqz v3, :cond_12

    invoke-virtual {v2}, Ljava/lang/String;->length()I

    move-result v2

    if-nez v2, :cond_a

    goto/16 :goto_7

    :cond_a
    iget-object v2, v0, Llyiahf/vczjk/id8;->OooO0Oo:Llyiahf/vczjk/mm9;

    iget-object v2, v2, Llyiahf/vczjk/mm9;->OooO00o:Llyiahf/vczjk/lm9;

    iget-object v2, v2, Llyiahf/vczjk/lm9;->OooO00o:Llyiahf/vczjk/an;

    iget-object v2, v2, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    invoke-virtual {v2}, Ljava/lang/String;->length()I

    move-result v4

    const/4 v5, 0x2

    const/4 v6, 0x0

    const/4 v7, 0x1

    const/4 v8, 0x0

    iget-boolean p1, p1, Llyiahf/vczjk/hl1;->OooOOO:Z

    iget v9, v0, Llyiahf/vczjk/id8;->OooO00o:I

    if-nez v9, :cond_c

    invoke-static {v6, v2}, Llyiahf/vczjk/mt6;->OooOOO(ILjava/lang/String;)I

    move-result v2

    if-eqz p1, :cond_b

    iget-object p1, v1, Llyiahf/vczjk/ld8;->OooO00o:Llyiahf/vczjk/kd8;

    invoke-static {p1, v0, v2}, Llyiahf/vczjk/ru6;->OooOO0o(Llyiahf/vczjk/kd8;Llyiahf/vczjk/id8;I)Llyiahf/vczjk/kd8;

    move-result-object p1

    invoke-static {v1, p1, v8, v7, v5}, Llyiahf/vczjk/ld8;->OooO00o(Llyiahf/vczjk/ld8;Llyiahf/vczjk/kd8;Llyiahf/vczjk/kd8;ZI)Llyiahf/vczjk/ld8;

    move-result-object p1

    :goto_5
    move-object v0, p1

    goto :goto_8

    :cond_b
    iget-object p1, v1, Llyiahf/vczjk/ld8;->OooO0O0:Llyiahf/vczjk/kd8;

    invoke-static {p1, v0, v2}, Llyiahf/vczjk/ru6;->OooOO0o(Llyiahf/vczjk/kd8;Llyiahf/vczjk/id8;I)Llyiahf/vczjk/kd8;

    move-result-object p1

    invoke-static {v1, v8, p1, v6, v7}, Llyiahf/vczjk/ld8;->OooO00o(Llyiahf/vczjk/ld8;Llyiahf/vczjk/kd8;Llyiahf/vczjk/kd8;ZI)Llyiahf/vczjk/ld8;

    move-result-object p1

    goto :goto_5

    :cond_c
    if-ne v9, v4, :cond_e

    invoke-static {v4, v2}, Llyiahf/vczjk/mt6;->OooOOOO(ILjava/lang/String;)I

    move-result v2

    if-eqz p1, :cond_d

    iget-object p1, v1, Llyiahf/vczjk/ld8;->OooO00o:Llyiahf/vczjk/kd8;

    invoke-static {p1, v0, v2}, Llyiahf/vczjk/ru6;->OooOO0o(Llyiahf/vczjk/kd8;Llyiahf/vczjk/id8;I)Llyiahf/vczjk/kd8;

    move-result-object p1

    invoke-static {v1, p1, v8, v6, v5}, Llyiahf/vczjk/ld8;->OooO00o(Llyiahf/vczjk/ld8;Llyiahf/vczjk/kd8;Llyiahf/vczjk/kd8;ZI)Llyiahf/vczjk/ld8;

    move-result-object p1

    goto :goto_5

    :cond_d
    iget-object p1, v1, Llyiahf/vczjk/ld8;->OooO0O0:Llyiahf/vczjk/kd8;

    invoke-static {p1, v0, v2}, Llyiahf/vczjk/ru6;->OooOO0o(Llyiahf/vczjk/kd8;Llyiahf/vczjk/id8;I)Llyiahf/vczjk/kd8;

    move-result-object p1

    invoke-static {v1, v8, p1, v7, v7}, Llyiahf/vczjk/ld8;->OooO00o(Llyiahf/vczjk/ld8;Llyiahf/vczjk/kd8;Llyiahf/vczjk/kd8;ZI)Llyiahf/vczjk/ld8;

    move-result-object p1

    goto :goto_5

    :cond_e
    iget-boolean v3, v3, Llyiahf/vczjk/ld8;->OooO0OO:Z

    if-ne v3, v7, :cond_f

    move v6, v7

    :cond_f
    xor-int v3, p1, v6

    if-eqz v3, :cond_10

    invoke-static {v9, v2}, Llyiahf/vczjk/mt6;->OooOOOO(ILjava/lang/String;)I

    move-result v2

    goto :goto_6

    :cond_10
    invoke-static {v9, v2}, Llyiahf/vczjk/mt6;->OooOOO(ILjava/lang/String;)I

    move-result v2

    :goto_6
    if-eqz p1, :cond_11

    iget-object p1, v1, Llyiahf/vczjk/ld8;->OooO00o:Llyiahf/vczjk/kd8;

    invoke-static {p1, v0, v2}, Llyiahf/vczjk/ru6;->OooOO0o(Llyiahf/vczjk/kd8;Llyiahf/vczjk/id8;I)Llyiahf/vczjk/kd8;

    move-result-object p1

    invoke-static {v1, p1, v8, v6, v5}, Llyiahf/vczjk/ld8;->OooO00o(Llyiahf/vczjk/ld8;Llyiahf/vczjk/kd8;Llyiahf/vczjk/kd8;ZI)Llyiahf/vczjk/ld8;

    move-result-object p1

    goto :goto_5

    :cond_11
    iget-object p1, v1, Llyiahf/vczjk/ld8;->OooO0O0:Llyiahf/vczjk/kd8;

    invoke-static {p1, v0, v2}, Llyiahf/vczjk/ru6;->OooOO0o(Llyiahf/vczjk/kd8;Llyiahf/vczjk/id8;I)Llyiahf/vczjk/kd8;

    move-result-object p1

    invoke-static {v1, v8, p1, v6, v7}, Llyiahf/vczjk/ld8;->OooO00o(Llyiahf/vczjk/ld8;Llyiahf/vczjk/kd8;Llyiahf/vczjk/kd8;ZI)Llyiahf/vczjk/ld8;

    move-result-object p1

    goto :goto_5

    :cond_12
    :goto_7
    move-object v0, v1

    :goto_8
    return-object v0

    :pswitch_0
    sget-object v0, Llyiahf/vczjk/vp3;->OooOo00:Llyiahf/vczjk/vp3;

    invoke-static {p1, v0}, Llyiahf/vczjk/ru6;->OooO0oo(Llyiahf/vczjk/hl1;Llyiahf/vczjk/sg0;)Llyiahf/vczjk/ld8;

    move-result-object p1

    return-object p1

    :pswitch_1
    sget-object v0, Llyiahf/vczjk/wp3;->OooOo00:Llyiahf/vczjk/wp3;

    invoke-static {p1, v0}, Llyiahf/vczjk/ru6;->OooO0oo(Llyiahf/vczjk/hl1;Llyiahf/vczjk/sg0;)Llyiahf/vczjk/ld8;

    move-result-object p1

    return-object p1

    :pswitch_2
    new-instance v0, Llyiahf/vczjk/ld8;

    iget-object v1, p1, Llyiahf/vczjk/hl1;->OooOOOo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/id8;

    iget v2, v1, Llyiahf/vczjk/id8;->OooO00o:I

    invoke-virtual {v1, v2}, Llyiahf/vczjk/id8;->OooO00o(I)Llyiahf/vczjk/kd8;

    move-result-object v2

    iget v3, v1, Llyiahf/vczjk/id8;->OooO0O0:I

    invoke-virtual {v1, v3}, Llyiahf/vczjk/id8;->OooO00o(I)Llyiahf/vczjk/kd8;

    move-result-object v1

    invoke-virtual {p1}, Llyiahf/vczjk/hl1;->OooO0o()Llyiahf/vczjk/vs1;

    move-result-object p1

    sget-object v3, Llyiahf/vczjk/vs1;->OooOOO0:Llyiahf/vczjk/vs1;

    if-ne p1, v3, :cond_13

    const/4 p1, 0x1

    goto :goto_9

    :cond_13
    const/4 p1, 0x0

    :goto_9
    invoke-direct {v0, v2, v1, p1}, Llyiahf/vczjk/ld8;-><init>(Llyiahf/vczjk/kd8;Llyiahf/vczjk/kd8;Z)V

    return-object v0

    :pswitch_data_0
    .packed-switch 0xe
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public OooO0oo(D)D
    .locals 0

    return-wide p1
.end method

.method public accept(Ljava/lang/Object;)V
    .locals 0

    check-cast p1, Ljava/lang/Throwable;

    sget p1, Llyiahf/vczjk/tn6;->OooO00o:I

    add-int/lit8 p1, p1, 0x1

    sput p1, Llyiahf/vczjk/tn6;->OooO00o:I

    return-void
.end method

.method public apply(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/yz2;->OooOOO0:I

    sparse-switch v0, :sswitch_data_0

    check-cast p1, Lgithub/tornaco/android/thanos/core/secure/field/Fields;

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/secure/field/Fields;->getNetCountryIso()Ljava/lang/String;

    move-result-object p1

    return-object p1

    :sswitch_0
    check-cast p1, Lgithub/tornaco/android/thanos/core/secure/field/Fields;

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/secure/field/Fields;->getNetOperatorName()Ljava/lang/String;

    move-result-object p1

    return-object p1

    :sswitch_1
    check-cast p1, Lgithub/tornaco/android/thanos/core/secure/field/Fields;

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/secure/field/Fields;->getNetOperator()Ljava/lang/String;

    move-result-object p1

    return-object p1

    :sswitch_2
    check-cast p1, Lgithub/tornaco/android/thanos/core/secure/field/Fields;

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/secure/field/Fields;->getSimOperator()Ljava/lang/String;

    move-result-object p1

    return-object p1

    :sswitch_3
    check-cast p1, Lgithub/tornaco/android/thanos/core/secure/field/Fields;

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/secure/field/Fields;->getSimOperatorName()Ljava/lang/String;

    move-result-object p1

    return-object p1

    :sswitch_4
    check-cast p1, Lgithub/tornaco/android/thanos/core/secure/field/Fields;

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/secure/field/Fields;->getSimCountryIso()Ljava/lang/String;

    move-result-object p1

    return-object p1

    :sswitch_5
    check-cast p1, Lgithub/tornaco/android/thanos/core/secure/field/Fields;

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/secure/field/Fields;->getSimSerial()Ljava/lang/String;

    move-result-object p1

    return-object p1

    :sswitch_6
    check-cast p1, Lgithub/tornaco/android/thanos/core/secure/field/Fields;

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/secure/field/Fields;->getLine1Number()Ljava/lang/String;

    move-result-object p1

    return-object p1

    :sswitch_7
    check-cast p1, Lgithub/tornaco/android/thanos/core/compat/Pair;

    invoke-static {p1}, Lgithub/tornaco/android/thanos/services/xposed/hooks/privacy/TelephonyManagerRegistry;->OooO00o(Lgithub/tornaco/android/thanos/core/compat/Pair;)Ljava/lang/String;

    move-result-object p1

    return-object p1

    :sswitch_8
    check-cast p1, Lgithub/tornaco/android/thanos/core/compat/Pair;

    invoke-static {p1}, Lgithub/tornaco/android/thanos/services/xposed/hooks/privacy/TelephonyManagerRegistry;->OooO0O0(Lgithub/tornaco/android/thanos/core/compat/Pair;)Ljava/lang/String;

    move-result-object p1

    return-object p1

    :sswitch_9
    check-cast p1, Lgithub/tornaco/android/thanos/core/secure/field/Fields;

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/secure/field/Fields;->getDeviceId()Ljava/lang/String;

    move-result-object p1

    return-object p1

    :sswitch_a
    invoke-static {p1}, Lorg/apache/commons/io/function/IOUnaryOperator;->OooOOoo(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :sswitch_b
    check-cast p1, Ljava/io/File;

    invoke-static {p1}, Lorg/apache/commons/io/FileUtils;->lastModified(Ljava/io/File;)J

    move-result-wide v0

    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object p1

    return-object p1

    :sswitch_data_0
    .sparse-switch
        0x0 -> :sswitch_b
        0x2 -> :sswitch_a
        0x13 -> :sswitch_9
        0x14 -> :sswitch_8
        0x15 -> :sswitch_7
        0x16 -> :sswitch_6
        0x17 -> :sswitch_5
        0x18 -> :sswitch_4
        0x19 -> :sswitch_3
        0x1a -> :sswitch_2
        0x1b -> :sswitch_1
        0x1c -> :sswitch_0
    .end sparse-switch
.end method

.method public get()Ljava/lang/Object;
    .locals 1

    invoke-static {}, Lorg/apache/commons/io/IOUtils;->OooO00o()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public isMatch(Ljava/lang/CharSequence;)Z
    .locals 1

    iget v0, p0, Llyiahf/vczjk/yz2;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    invoke-static {p1}, Lorg/apache/commons/codec/language/bm/Rule;->OooOO0(Ljava/lang/CharSequence;)Z

    move-result p1

    return p1

    :pswitch_0
    invoke-static {p1}, Lorg/apache/commons/codec/language/bm/Rule;->OooO0Oo(Ljava/lang/CharSequence;)Z

    move-result p1

    return p1

    nop

    :pswitch_data_0
    .packed-switch 0xc
        :pswitch_0
    .end packed-switch
.end method

.method public run()V
    .locals 3

    sget-object v0, Llyiahf/vczjk/uv6;->OoooOOO:Ljava/util/ArrayList;

    new-instance v1, Llyiahf/vczjk/oO00Oo00;

    const/4 v2, 0x6

    invoke-direct {v1, v2}, Llyiahf/vczjk/oO00Oo00;-><init>(I)V

    invoke-static {v0, v1}, Lutil/CollectionUtils;->consumeRemaining(Ljava/util/Collection;Lutil/Consumer;)V

    return-void
.end method

.method public test(Ljava/lang/Object;)Z
    .locals 0

    invoke-static {p1}, Ljava/util/Objects;->isNull(Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method
