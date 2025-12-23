.class public final synthetic Llyiahf/vczjk/m99;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    const/4 p1, 0x0

    iput p1, p0, Llyiahf/vczjk/m99;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(IB)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/m99;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    const/4 v0, 0x0

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v2, 0x1

    iget v3, p0, Llyiahf/vczjk/m99;->OooOOO0:I

    packed-switch v3, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/uh6;

    check-cast p2, Llyiahf/vczjk/uh6;

    sget-object v0, Ljava/util/Locale;->CHINESE:Ljava/util/Locale;

    invoke-static {v0}, Ljava/text/Collator;->getInstance(Ljava/util/Locale;)Ljava/text/Collator;

    move-result-object v0

    iget-object p1, p1, Llyiahf/vczjk/uh6;->OooO00o:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getAppLabel()Ljava/lang/String;

    move-result-object p1

    iget-object p2, p2, Llyiahf/vczjk/uh6;->OooO00o:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-virtual {p2}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getAppLabel()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {v0, p1, p2}, Ljava/text/Collator;->compare(Ljava/lang/String;Ljava/lang/String;)I

    move-result p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    return-object p1

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/n58;

    check-cast p2, Llyiahf/vczjk/kx9;

    iget p1, p2, Llyiahf/vczjk/kx9;->OooO00o:F

    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object p1

    invoke-virtual {p2}, Llyiahf/vczjk/kx9;->OooO0O0()F

    move-result v0

    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v0

    iget-object p2, p2, Llyiahf/vczjk/kx9;->OooO0O0:Llyiahf/vczjk/lr5;

    check-cast p2, Llyiahf/vczjk/zv8;

    invoke-virtual {p2}, Llyiahf/vczjk/zv8;->OooOOoo()F

    move-result p2

    invoke-static {p2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object p2

    filled-new-array {p1, v0, p2}, [Ljava/lang/Float;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object p1

    return-object p1

    :pswitch_1
    check-cast p1, Llyiahf/vczjk/br9;

    check-cast p2, Llyiahf/vczjk/mr1;

    instance-of v0, p2, Llyiahf/vczjk/uq9;

    if-eqz v0, :cond_0

    check-cast p2, Llyiahf/vczjk/uq9;

    iget-object v0, p1, Llyiahf/vczjk/br9;->OooO00o:Llyiahf/vczjk/or1;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/uq9;->OooO0O0(Llyiahf/vczjk/or1;)Ljava/lang/Object;

    move-result-object v0

    iget v1, p1, Llyiahf/vczjk/br9;->OooO0Oo:I

    iget-object v3, p1, Llyiahf/vczjk/br9;->OooO0O0:[Ljava/lang/Object;

    aput-object v0, v3, v1

    add-int/2addr v2, v1

    iput v2, p1, Llyiahf/vczjk/br9;->OooO0Oo:I

    iget-object v0, p1, Llyiahf/vczjk/br9;->OooO0OO:[Llyiahf/vczjk/uq9;

    aput-object p2, v0, v1

    :cond_0
    return-object p1

    :pswitch_2
    check-cast p1, Llyiahf/vczjk/uq9;

    check-cast p2, Llyiahf/vczjk/mr1;

    if-eqz p1, :cond_1

    move-object v0, p1

    goto :goto_0

    :cond_1
    instance-of p1, p2, Llyiahf/vczjk/uq9;

    if-eqz p1, :cond_2

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/uq9;

    :cond_2
    :goto_0
    return-object v0

    :pswitch_3
    check-cast p2, Llyiahf/vczjk/mr1;

    instance-of v1, p2, Llyiahf/vczjk/uq9;

    if-eqz v1, :cond_6

    instance-of v1, p1, Ljava/lang/Integer;

    if-eqz v1, :cond_3

    move-object v0, p1

    check-cast v0, Ljava/lang/Integer;

    :cond_3
    if-eqz v0, :cond_4

    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    move-result p1

    goto :goto_1

    :cond_4
    move p1, v2

    :goto_1
    if-nez p1, :cond_5

    move-object p1, p2

    goto :goto_2

    :cond_5
    add-int/2addr p1, v2

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    :cond_6
    :goto_2
    return-object p1

    :pswitch_4
    check-cast p1, Landroid/content/Context;

    check-cast p2, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    const-string v0, "<unused var>"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v1

    :pswitch_5
    check-cast p1, Landroid/content/Context;

    check-cast p2, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    sget v0, Lnow/fortuitous/thanos/ThanosApp;->OooOOOO:I

    const-string v0, "context"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "app"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/rz7;

    const/4 v2, 0x2

    invoke-direct {v0, p1, p2, v2}, Llyiahf/vczjk/rz7;-><init>(Landroid/content/Context;Lgithub/tornaco/android/thanos/core/pm/AppInfo;I)V

    invoke-static {p1}, Llyiahf/vczjk/dn8;->o00Ooo(Landroid/content/Context;)Z

    move-result v2

    if-eqz v2, :cond_7

    invoke-static {p1}, Lcom/bumptech/glide/Glide;->with(Landroid/content/Context;)Lcom/bumptech/glide/RequestManager;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/ci3;

    invoke-virtual {v2}, Llyiahf/vczjk/ci3;->OooO00o()Llyiahf/vczjk/ai3;

    move-result-object v2

    invoke-virtual {v2, p2}, Llyiahf/vczjk/ai3;->OooO0o0(Ljava/lang/Object;)Llyiahf/vczjk/ai3;

    move-result-object v2

    sget v3, Lgithub/tornaco/android/thanos/module/common/R$mipmap;->ic_fallback_app_icon:I

    invoke-virtual {v2, v3}, Llyiahf/vczjk/ai3;->OooO0OO(I)Llyiahf/vczjk/ai3;

    move-result-object v2

    sget v3, Lgithub/tornaco/android/thanos/module/common/R$mipmap;->ic_fallback_app_icon:I

    invoke-virtual {v2, v3}, Llyiahf/vczjk/ai3;->OooO0Oo(I)Llyiahf/vczjk/ai3;

    move-result-object v2

    new-instance v3, Llyiahf/vczjk/en8;

    invoke-direct {v3, v0, p1, p2}, Llyiahf/vczjk/en8;-><init>(Llyiahf/vczjk/le3;Landroid/content/Context;Lgithub/tornaco/android/thanos/core/pm/AppInfo;)V

    invoke-virtual {v2, v3}, Lcom/bumptech/glide/RequestBuilder;->into(Lcom/bumptech/glide/request/target/Target;)Lcom/bumptech/glide/request/target/Target;

    :cond_7
    return-object v1

    :pswitch_6
    check-cast p1, Llyiahf/vczjk/ef5;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    move-result p2

    invoke-interface {p1, p2}, Llyiahf/vczjk/ef5;->OooO0OO(I)I

    move-result p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    return-object p1

    :pswitch_7
    check-cast p1, Llyiahf/vczjk/ef5;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    move-result p2

    invoke-interface {p1, p2}, Llyiahf/vczjk/ef5;->OooooO0(I)I

    move-result p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    return-object p1

    :pswitch_8
    check-cast p1, Llyiahf/vczjk/ef5;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    move-result p2

    invoke-interface {p1, p2}, Llyiahf/vczjk/ef5;->OooOo0o(I)I

    move-result p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    return-object p1

    :pswitch_9
    check-cast p1, Llyiahf/vczjk/ef5;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    move-result p2

    invoke-interface {p1, p2}, Llyiahf/vczjk/ef5;->OooOo0(I)I

    move-result p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    return-object p1

    :pswitch_a
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    invoke-static {p2, p1}, Llyiahf/vczjk/ll6;->OooO0OO(ILlyiahf/vczjk/rf1;)V

    return-object v1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
