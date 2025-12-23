.class public final Llyiahf/vczjk/jz;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/dx2;


# instance fields
.field public final synthetic OooO00o:I

.field public final OooO0O0:Landroid/net/Uri;

.field public final OooO0OO:Llyiahf/vczjk/hf6;


# direct methods
.method public synthetic constructor <init>(Landroid/net/Uri;Llyiahf/vczjk/hf6;I)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/jz;->OooO00o:I

    iput-object p1, p0, Llyiahf/vczjk/jz;->OooO0O0:Landroid/net/Uri;

    iput-object p2, p0, Llyiahf/vczjk/jz;->OooO0OO:Llyiahf/vczjk/hf6;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 10

    const/4 p1, 0x3

    const/4 v0, 0x2

    const/4 v1, 0x0

    const/4 v2, 0x1

    iget-object v3, p0, Llyiahf/vczjk/jz;->OooO0OO:Llyiahf/vczjk/hf6;

    iget-object v4, p0, Llyiahf/vczjk/jz;->OooO0O0:Landroid/net/Uri;

    iget v5, p0, Llyiahf/vczjk/jz;->OooO00o:I

    packed-switch v5, :pswitch_data_0

    invoke-virtual {v4}, Landroid/net/Uri;->getAuthority()Ljava/lang/String;

    move-result-object p1

    const-string v5, "Invalid android.resource URI: "

    if-eqz p1, :cond_c

    invoke-static {p1}, Llyiahf/vczjk/z69;->OoooOO0(Ljava/lang/CharSequence;)Z

    move-result v6

    if-nez v6, :cond_0

    move-object v1, p1

    :cond_0
    if-eqz v1, :cond_c

    invoke-virtual {v4}, Landroid/net/Uri;->getPathSegments()Ljava/util/List;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/d21;->o0OO00O(Ljava/util/List;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/String;

    if-eqz p1, :cond_b

    invoke-static {p1}, Llyiahf/vczjk/g79;->Oooo0(Ljava/lang/String;)Ljava/lang/Integer;

    move-result-object p1

    if-eqz p1, :cond_b

    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    move-result p1

    iget-object v4, v3, Llyiahf/vczjk/hf6;->OooO00o:Landroid/content/Context;

    invoke-virtual {v4}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v1, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_1

    invoke-virtual {v4}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v5

    goto :goto_0

    :cond_1
    invoke-virtual {v4}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object v5

    invoke-virtual {v5, v1}, Landroid/content/pm/PackageManager;->getResourcesForApplication(Ljava/lang/String;)Landroid/content/res/Resources;

    move-result-object v5

    :goto_0
    new-instance v6, Landroid/util/TypedValue;

    invoke-direct {v6}, Landroid/util/TypedValue;-><init>()V

    invoke-virtual {v5, p1, v6, v2}, Landroid/content/res/Resources;->getValue(ILandroid/util/TypedValue;Z)V

    iget-object v6, v6, Landroid/util/TypedValue;->string:Ljava/lang/CharSequence;

    const/4 v7, 0x6

    const/16 v8, 0x2f

    const/4 v9, 0x0

    invoke-static {v8, v9, v7, v6}, Llyiahf/vczjk/z69;->OoooOOO(CIILjava/lang/CharSequence;)I

    move-result v7

    invoke-interface {v6}, Ljava/lang/CharSequence;->length()I

    move-result v8

    invoke-interface {v6, v7, v8}, Ljava/lang/CharSequence;->subSequence(II)Ljava/lang/CharSequence;

    move-result-object v6

    invoke-virtual {v6}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v6

    invoke-static {}, Landroid/webkit/MimeTypeMap;->getSingleton()Landroid/webkit/MimeTypeMap;

    move-result-object v7

    invoke-static {v7, v6}, Llyiahf/vczjk/OooOOO0;->OooO0O0(Landroid/webkit/MimeTypeMap;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v6

    const-string v7, "text/xml"

    invoke-static {v6, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_a

    invoke-virtual {v4}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    move-result-object v6

    invoke-virtual {v1, v6}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    const-string v6, "Invalid resource ID: "

    if-eqz v1, :cond_3

    invoke-static {v4, p1}, Llyiahf/vczjk/vc6;->OooOoO(Landroid/content/Context;I)Landroid/graphics/drawable/Drawable;

    move-result-object v0

    if-eqz v0, :cond_2

    goto :goto_2

    :cond_2
    invoke-static {p1, v6}, Llyiahf/vczjk/ii5;->OooO0o0(ILjava/lang/String;)Ljava/lang/String;

    move-result-object p1

    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_3
    invoke-virtual {v5, p1}, Landroid/content/res/Resources;->getXml(I)Landroid/content/res/XmlResourceParser;

    move-result-object v1

    invoke-interface {v1}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    move-result v7

    :goto_1
    if-eq v7, v0, :cond_4

    if-eq v7, v2, :cond_4

    invoke-interface {v1}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    move-result v7

    goto :goto_1

    :cond_4
    if-ne v7, v0, :cond_9

    invoke-virtual {v4}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/es7;->OooO00o:Ljava/lang/ThreadLocal;

    invoke-virtual {v5, p1, v0}, Landroid/content/res/Resources;->getDrawable(ILandroid/content/res/Resources$Theme;)Landroid/graphics/drawable/Drawable;

    move-result-object v0

    if-eqz v0, :cond_8

    :goto_2
    instance-of p1, v0, Landroid/graphics/drawable/VectorDrawable;

    if-nez p1, :cond_6

    instance-of p1, v0, Llyiahf/vczjk/qda;

    if-eqz p1, :cond_5

    goto :goto_3

    :cond_5
    move v2, v9

    :cond_6
    :goto_3
    new-instance p1, Llyiahf/vczjk/sg2;

    if-eqz v2, :cond_7

    iget-object v1, v3, Llyiahf/vczjk/hf6;->OooO0O0:Landroid/graphics/Bitmap$Config;

    iget-object v5, v3, Llyiahf/vczjk/hf6;->OooO0Oo:Llyiahf/vczjk/sq8;

    iget-object v6, v3, Llyiahf/vczjk/hf6;->OooO0o0:Llyiahf/vczjk/r78;

    iget-boolean v3, v3, Llyiahf/vczjk/hf6;->OooO0o:Z

    invoke-static {v0, v1, v5, v6, v3}, Llyiahf/vczjk/cp7;->OooOOo0(Landroid/graphics/drawable/Drawable;Landroid/graphics/Bitmap$Config;Llyiahf/vczjk/sq8;Llyiahf/vczjk/r78;Z)Landroid/graphics/Bitmap;

    move-result-object v0

    invoke-virtual {v4}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v1

    new-instance v3, Landroid/graphics/drawable/BitmapDrawable;

    invoke-direct {v3, v1, v0}, Landroid/graphics/drawable/BitmapDrawable;-><init>(Landroid/content/res/Resources;Landroid/graphics/Bitmap;)V

    move-object v0, v3

    :cond_7
    sget-object v1, Llyiahf/vczjk/zx1;->OooOOOO:Llyiahf/vczjk/zx1;

    invoke-direct {p1, v0, v2, v1}, Llyiahf/vczjk/sg2;-><init>(Landroid/graphics/drawable/Drawable;ZLlyiahf/vczjk/zx1;)V

    goto :goto_4

    :cond_8
    invoke-static {p1, v6}, Llyiahf/vczjk/ii5;->OooO0o0(ILjava/lang/String;)Ljava/lang/String;

    move-result-object p1

    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_9
    new-instance p1, Lorg/xmlpull/v1/XmlPullParserException;

    const-string v0, "No start tag found."

    invoke-direct {p1, v0}, Lorg/xmlpull/v1/XmlPullParserException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_a
    new-instance v0, Landroid/util/TypedValue;

    invoke-direct {v0}, Landroid/util/TypedValue;-><init>()V

    invoke-virtual {v5, p1, v0}, Landroid/content/res/Resources;->openRawResource(ILandroid/util/TypedValue;)Ljava/io/InputStream;

    move-result-object p1

    new-instance v1, Llyiahf/vczjk/by8;

    invoke-static {p1}, Llyiahf/vczjk/ng0;->OoooOo0(Ljava/io/InputStream;)Llyiahf/vczjk/z00;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/ng0;->OooOOO(Llyiahf/vczjk/rx8;)Llyiahf/vczjk/ih7;

    move-result-object p1

    new-instance v2, Llyiahf/vczjk/zr7;

    iget v0, v0, Landroid/util/TypedValue;->density:I

    invoke-direct {v2, v0}, Llyiahf/vczjk/zr7;-><init>(I)V

    new-instance v0, Llyiahf/vczjk/tx8;

    invoke-direct {v0, p1, v2}, Llyiahf/vczjk/tx8;-><init>(Llyiahf/vczjk/nj0;Llyiahf/vczjk/qqa;)V

    sget-object p1, Llyiahf/vczjk/zx1;->OooOOOO:Llyiahf/vczjk/zx1;

    invoke-direct {v1, v0, v6, p1}, Llyiahf/vczjk/by8;-><init>(Llyiahf/vczjk/nv3;Ljava/lang/String;Llyiahf/vczjk/zx1;)V

    move-object p1, v1

    :goto_4
    return-object p1

    :cond_b
    new-instance p1, Ljava/lang/IllegalStateException;

    invoke-static {v4, v5}, Llyiahf/vczjk/q99;->OooO0oO(Landroid/net/Uri;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_c
    new-instance p1, Ljava/lang/IllegalStateException;

    invoke-static {v4, v5}, Llyiahf/vczjk/q99;->OooO0oO(Landroid/net/Uri;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :pswitch_0
    iget-object v5, v3, Llyiahf/vczjk/hf6;->OooO00o:Landroid/content/Context;

    invoke-virtual {v5}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;

    move-result-object v5

    invoke-virtual {v4}, Landroid/net/Uri;->getAuthority()Ljava/lang/String;

    move-result-object v6

    const-string v7, "com.android.contacts"

    invoke-static {v6, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    const-string v7, "\'."

    if-eqz v6, :cond_f

    invoke-virtual {v4}, Landroid/net/Uri;->getLastPathSegment()Ljava/lang/String;

    move-result-object v6

    const-string v8, "display_photo"

    invoke-static {v6, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_f

    const-string p1, "r"

    invoke-virtual {v5, v4, p1}, Landroid/content/ContentResolver;->openAssetFileDescriptor(Landroid/net/Uri;Ljava/lang/String;)Landroid/content/res/AssetFileDescriptor;

    move-result-object p1

    if-eqz p1, :cond_d

    invoke-virtual {p1}, Landroid/content/res/AssetFileDescriptor;->createInputStream()Ljava/io/FileInputStream;

    move-result-object v1

    :cond_d
    if-eqz v1, :cond_e

    goto/16 :goto_9

    :cond_e
    new-instance p1, Ljava/lang/StringBuilder;

    const-string v0, "Unable to find a contact photo associated with \'"

    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p1, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_f
    sget v6, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v8, 0x1d

    if-lt v6, v8, :cond_16

    invoke-virtual {v4}, Landroid/net/Uri;->getAuthority()Ljava/lang/String;

    move-result-object v6

    const-string v8, "media"

    invoke-static {v6, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_10

    goto/16 :goto_8

    :cond_10
    invoke-virtual {v4}, Landroid/net/Uri;->getPathSegments()Ljava/util/List;

    move-result-object v6

    invoke-interface {v6}, Ljava/util/List;->size()I

    move-result v8

    if-lt v8, p1, :cond_16

    add-int/lit8 p1, v8, -0x3

    invoke-interface {v6, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    const-string v9, "audio"

    invoke-static {p1, v9}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_16

    sub-int/2addr v8, v0

    invoke-interface {v6, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    const-string v0, "albums"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_16

    iget-object p1, v3, Llyiahf/vczjk/hf6;->OooO0Oo:Llyiahf/vczjk/sq8;

    iget-object v0, p1, Llyiahf/vczjk/sq8;->OooO00o:Llyiahf/vczjk/sb;

    instance-of v3, v0, Llyiahf/vczjk/ob2;

    if-eqz v3, :cond_11

    check-cast v0, Llyiahf/vczjk/ob2;

    goto :goto_5

    :cond_11
    move-object v0, v1

    :goto_5
    if-eqz v0, :cond_13

    iget-object p1, p1, Llyiahf/vczjk/sq8;->OooO0O0:Llyiahf/vczjk/sb;

    instance-of v3, p1, Llyiahf/vczjk/ob2;

    if-eqz v3, :cond_12

    check-cast p1, Llyiahf/vczjk/ob2;

    goto :goto_6

    :cond_12
    move-object p1, v1

    :goto_6
    if-eqz p1, :cond_13

    new-instance v3, Landroid/os/Bundle;

    invoke-direct {v3, v2}, Landroid/os/Bundle;-><init>(I)V

    new-instance v2, Landroid/graphics/Point;

    iget v0, v0, Llyiahf/vczjk/ob2;->OooOO0:I

    iget p1, p1, Llyiahf/vczjk/ob2;->OooOO0:I

    invoke-direct {v2, v0, p1}, Landroid/graphics/Point;-><init>(II)V

    const-string p1, "android.content.extra.SIZE"

    invoke-virtual {v3, p1, v2}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    goto :goto_7

    :cond_13
    move-object v3, v1

    :goto_7
    invoke-static {v5, v4, v3}, Llyiahf/vczjk/r9;->OooO0o0(Landroid/content/ContentResolver;Landroid/net/Uri;Landroid/os/Bundle;)Landroid/content/res/AssetFileDescriptor;

    move-result-object p1

    if-eqz p1, :cond_14

    invoke-virtual {p1}, Landroid/content/res/AssetFileDescriptor;->createInputStream()Ljava/io/FileInputStream;

    move-result-object v1

    :cond_14
    if-eqz v1, :cond_15

    goto :goto_9

    :cond_15
    new-instance p1, Ljava/lang/StringBuilder;

    const-string v0, "Unable to find a music thumbnail associated with \'"

    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p1, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_16
    :goto_8
    invoke-virtual {v5, v4}, Landroid/content/ContentResolver;->openInputStream(Landroid/net/Uri;)Ljava/io/InputStream;

    move-result-object v1

    if-eqz v1, :cond_17

    :goto_9
    new-instance p1, Llyiahf/vczjk/by8;

    invoke-static {v1}, Llyiahf/vczjk/ng0;->OoooOo0(Ljava/io/InputStream;)Llyiahf/vczjk/z00;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/ng0;->OooOOO(Llyiahf/vczjk/rx8;)Llyiahf/vczjk/ih7;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/hz;

    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    new-instance v2, Llyiahf/vczjk/tx8;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/tx8;-><init>(Llyiahf/vczjk/nj0;Llyiahf/vczjk/qqa;)V

    invoke-virtual {v5, v4}, Landroid/content/ContentResolver;->getType(Landroid/net/Uri;)Ljava/lang/String;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/zx1;->OooOOOO:Llyiahf/vczjk/zx1;

    invoke-direct {p1, v2, v0, v1}, Llyiahf/vczjk/by8;-><init>(Llyiahf/vczjk/nv3;Ljava/lang/String;Llyiahf/vczjk/zx1;)V

    return-object p1

    :cond_17
    new-instance p1, Ljava/lang/StringBuilder;

    const-string v0, "Unable to open \'"

    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p1, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :pswitch_1
    invoke-virtual {v4}, Landroid/net/Uri;->getPathSegments()Ljava/util/List;

    move-result-object p1

    invoke-static {v2, p1}, Llyiahf/vczjk/d21;->o0OoOo0(ILjava/util/List;)Ljava/util/List;

    move-result-object v4

    const/4 v7, 0x0

    const/4 v8, 0x0

    const-string v5, "/"

    const/4 v6, 0x0

    const/16 v9, 0x3e

    invoke-static/range {v4 .. v9}, Llyiahf/vczjk/d21;->o0ooOoO(Ljava/lang/Iterable;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;I)Ljava/lang/String;

    move-result-object p1

    new-instance v0, Llyiahf/vczjk/by8;

    iget-object v1, v3, Llyiahf/vczjk/hf6;->OooO00o:Landroid/content/Context;

    invoke-virtual {v1}, Landroid/content/Context;->getAssets()Landroid/content/res/AssetManager;

    move-result-object v1

    invoke-virtual {v1, p1}, Landroid/content/res/AssetManager;->open(Ljava/lang/String;)Ljava/io/InputStream;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/ng0;->OoooOo0(Ljava/io/InputStream;)Llyiahf/vczjk/z00;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/ng0;->OooOOO(Llyiahf/vczjk/rx8;)Llyiahf/vczjk/ih7;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/hz;

    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    new-instance v3, Llyiahf/vczjk/tx8;

    invoke-direct {v3, v1, v2}, Llyiahf/vczjk/tx8;-><init>(Llyiahf/vczjk/nj0;Llyiahf/vczjk/qqa;)V

    invoke-static {}, Landroid/webkit/MimeTypeMap;->getSingleton()Landroid/webkit/MimeTypeMap;

    move-result-object v1

    invoke-static {v1, p1}, Llyiahf/vczjk/OooOOO0;->OooO0O0(Landroid/webkit/MimeTypeMap;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    sget-object v1, Llyiahf/vczjk/zx1;->OooOOOO:Llyiahf/vczjk/zx1;

    invoke-direct {v0, v3, p1, v1}, Llyiahf/vczjk/by8;-><init>(Llyiahf/vczjk/nv3;Ljava/lang/String;Llyiahf/vczjk/zx1;)V

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
