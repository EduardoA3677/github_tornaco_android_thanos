.class public final Llyiahf/vczjk/io7;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $composition:Llyiahf/vczjk/z75;

.field final synthetic $context:Landroid/content/Context;

.field final synthetic $fontAssetsFolder:Ljava/lang/String;

.field final synthetic $fontFileExtension:Ljava/lang/String;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/z75;Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/io7;->$composition:Llyiahf/vczjk/z75;

    iput-object p2, p0, Llyiahf/vczjk/io7;->$context:Landroid/content/Context;

    iput-object p3, p0, Llyiahf/vczjk/io7;->$fontAssetsFolder:Ljava/lang/String;

    iput-object p4, p0, Llyiahf/vczjk/io7;->$fontFileExtension:Ljava/lang/String;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 6

    new-instance v0, Llyiahf/vczjk/io7;

    iget-object v1, p0, Llyiahf/vczjk/io7;->$composition:Llyiahf/vczjk/z75;

    iget-object v2, p0, Llyiahf/vczjk/io7;->$context:Landroid/content/Context;

    iget-object v3, p0, Llyiahf/vczjk/io7;->$fontAssetsFolder:Ljava/lang/String;

    iget-object v4, p0, Llyiahf/vczjk/io7;->$fontFileExtension:Ljava/lang/String;

    move-object v5, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/io7;-><init>(Llyiahf/vczjk/z75;Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/io7;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/io7;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/io7;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/io7;->label:I

    if-nez v0, :cond_5

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/io7;->$composition:Llyiahf/vczjk/z75;

    iget-object p1, p1, Llyiahf/vczjk/z75;->OooO0o:Ljava/util/HashMap;

    invoke-virtual {p1}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_4

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/w93;

    iget-object v1, p0, Llyiahf/vczjk/io7;->$context:Landroid/content/Context;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-object v2, p0, Llyiahf/vczjk/io7;->$fontAssetsFolder:Ljava/lang/String;

    iget-object v3, p0, Llyiahf/vczjk/io7;->$fontFileExtension:Ljava/lang/String;

    iget-object v4, v0, Llyiahf/vczjk/w93;->OooO0OO:Ljava/lang/String;

    invoke-static {v2}, Llyiahf/vczjk/ii5;->OooOOOO(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v2

    iget-object v5, v0, Llyiahf/vczjk/w93;->OooO00o:Ljava/lang/String;

    invoke-static {v2, v5, v3}, Llyiahf/vczjk/ix8;->OooOO0(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    :try_start_0
    invoke-virtual {v1}, Landroid/content/Context;->getAssets()Landroid/content/res/AssetManager;

    move-result-object v1

    invoke-static {v1, v2}, Landroid/graphics/Typeface;->createFromAsset(Landroid/content/res/AssetManager;Ljava/lang/String;)Landroid/graphics/Typeface;

    move-result-object v1
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_1

    :try_start_1
    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    const-string v2, "getStyle(...)"

    invoke-static {v4, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "Italic"

    const/4 v3, 0x0

    invoke-static {v4, v2, v3}, Llyiahf/vczjk/z69;->Oooo0OO(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Z)Z

    move-result v2

    const-string v5, "Bold"

    invoke-static {v4, v5, v3}, Llyiahf/vczjk/z69;->Oooo0OO(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Z)Z

    move-result v4

    if-eqz v2, :cond_0

    if-eqz v4, :cond_0

    const/4 v3, 0x3

    goto :goto_1

    :cond_0
    if-eqz v2, :cond_1

    const/4 v3, 0x2

    goto :goto_1

    :cond_1
    if-eqz v4, :cond_2

    const/4 v3, 0x1

    :cond_2
    :goto_1
    invoke-virtual {v1}, Landroid/graphics/Typeface;->getStyle()I

    move-result v2

    if-ne v2, v3, :cond_3

    goto :goto_2

    :cond_3
    invoke-static {v1, v3}, Landroid/graphics/Typeface;->create(Landroid/graphics/Typeface;I)Landroid/graphics/Typeface;

    move-result-object v1

    :goto_2
    iput-object v1, v0, Llyiahf/vczjk/w93;->OooO0Oo:Landroid/graphics/Typeface;
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    goto :goto_0

    :catch_0
    sget-object v0, Llyiahf/vczjk/p55;->OooO00o:Llyiahf/vczjk/n55;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    goto :goto_0

    :catch_1
    sget-object v0, Llyiahf/vczjk/p55;->OooO00o:Llyiahf/vczjk/n55;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    goto :goto_0

    :cond_4
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_5
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
