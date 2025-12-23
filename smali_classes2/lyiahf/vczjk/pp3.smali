.class public final Llyiahf/vczjk/pp3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/q01;
.implements Llyiahf/vczjk/nr1;
.implements Llyiahf/vczjk/rv1;
.implements Llyiahf/vczjk/gw8;
.implements Llyiahf/vczjk/dv8;
.implements Llyiahf/vczjk/rw;
.implements Llyiahf/vczjk/uw;
.implements Llyiahf/vczjk/en1;
.implements Llyiahf/vczjk/ac3;
.implements Llyiahf/vczjk/h05;
.implements Llyiahf/vczjk/xx6;
.implements Llyiahf/vczjk/qj8;


# static fields
.field public static final OooOOO:Llyiahf/vczjk/pp3;

.field public static final OooOOOO:Llyiahf/vczjk/pp3;

.field public static final OooOOOo:Llyiahf/vczjk/pp3;

.field public static final OooOOo:Llyiahf/vczjk/pp3;

.field public static final synthetic OooOOo0:Llyiahf/vczjk/pp3;

.field public static final OooOOoo:Llyiahf/vczjk/pp3;

.field public static final OooOo0:Llyiahf/vczjk/pp3;

.field public static final OooOo00:Llyiahf/vczjk/pp3;

.field public static final OooOo0O:Llyiahf/vczjk/ml9;


# instance fields
.field public final synthetic OooOOO0:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/pp3;

    const/4 v1, 0x1

    invoke-direct {v0, v1}, Llyiahf/vczjk/pp3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/pp3;->OooOOO:Llyiahf/vczjk/pp3;

    new-instance v0, Llyiahf/vczjk/pp3;

    const/4 v1, 0x2

    invoke-direct {v0, v1}, Llyiahf/vczjk/pp3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/pp3;->OooOOOO:Llyiahf/vczjk/pp3;

    new-instance v0, Llyiahf/vczjk/pp3;

    const/4 v1, 0x3

    invoke-direct {v0, v1}, Llyiahf/vczjk/pp3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/pp3;->OooOOOo:Llyiahf/vczjk/pp3;

    new-instance v0, Llyiahf/vczjk/pp3;

    const/4 v1, 0x4

    invoke-direct {v0, v1}, Llyiahf/vczjk/pp3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/pp3;->OooOOo0:Llyiahf/vczjk/pp3;

    new-instance v0, Llyiahf/vczjk/pp3;

    const/4 v1, 0x5

    invoke-direct {v0, v1}, Llyiahf/vczjk/pp3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/pp3;->OooOOo:Llyiahf/vczjk/pp3;

    new-instance v0, Llyiahf/vczjk/pp3;

    const/4 v1, 0x6

    invoke-direct {v0, v1}, Llyiahf/vczjk/pp3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/pp3;->OooOOoo:Llyiahf/vczjk/pp3;

    new-instance v0, Llyiahf/vczjk/pp3;

    const/4 v1, 0x7

    invoke-direct {v0, v1}, Llyiahf/vczjk/pp3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/pp3;->OooOo00:Llyiahf/vczjk/pp3;

    new-instance v0, Llyiahf/vczjk/pp3;

    const/16 v1, 0x8

    invoke-direct {v0, v1}, Llyiahf/vczjk/pp3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/pp3;->OooOo0:Llyiahf/vczjk/pp3;

    new-instance v0, Llyiahf/vczjk/ml9;

    const/16 v1, 0xb

    invoke-direct {v0, v1}, Llyiahf/vczjk/ml9;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/pp3;->OooOo0O:Llyiahf/vczjk/ml9;

    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/pp3;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static OooO0o(Ljava/lang/String;Llyiahf/vczjk/ib3;I)Landroid/graphics/Typeface;
    .locals 2

    if-nez p2, :cond_1

    sget-object v0, Llyiahf/vczjk/ib3;->OooOOoo:Llyiahf/vczjk/ib3;

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_1

    if-eqz p0, :cond_0

    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result v0

    if-nez v0, :cond_1

    :cond_0
    sget-object p0, Landroid/graphics/Typeface;->DEFAULT:Landroid/graphics/Typeface;

    return-object p0

    :cond_1
    const/4 v0, 0x0

    if-nez p0, :cond_2

    sget-object p0, Landroid/graphics/Typeface;->DEFAULT:Landroid/graphics/Typeface;

    goto :goto_0

    :cond_2
    invoke-static {p0, v0}, Landroid/graphics/Typeface;->create(Ljava/lang/String;I)Landroid/graphics/Typeface;

    move-result-object p0

    :goto_0
    iget p1, p1, Llyiahf/vczjk/ib3;->OooOOO0:I

    const/4 v1, 0x1

    if-ne p2, v1, :cond_3

    move v0, v1

    :cond_3
    invoke-static {p0, p1, v0}, Llyiahf/vczjk/a32;->OooO0Oo(Landroid/graphics/Typeface;IZ)Landroid/graphics/Typeface;

    move-result-object p0

    return-object p0
.end method

.method public static final OooO0o0(F[F[F)F
    .locals 7

    invoke-static {p0}, Ljava/lang/Math;->abs(F)F

    move-result v0

    invoke-static {p0}, Ljava/lang/Math;->signum(F)F

    move-result v1

    invoke-static {p1, v0}, Ljava/util/Arrays;->binarySearch([FF)I

    move-result v2

    if-ltz v2, :cond_0

    aget p0, p2, v2

    mul-float/2addr v1, p0

    return v1

    :cond_0
    add-int/lit8 v2, v2, 0x1

    neg-int v2, v2

    add-int/lit8 v3, v2, -0x1

    array-length v4, p1

    add-int/lit8 v4, v4, -0x1

    const/4 v5, 0x0

    if-lt v3, v4, :cond_2

    array-length v0, p1

    add-int/lit8 v0, v0, -0x1

    aget v0, p1, v0

    array-length p1, p1

    add-int/lit8 p1, p1, -0x1

    aget p1, p2, p1

    cmpg-float p2, v0, v5

    if-nez p2, :cond_1

    return v5

    :cond_1
    div-float/2addr p1, v0

    mul-float/2addr p1, p0

    return p1

    :cond_2
    const/4 p0, -0x1

    if-ne v3, p0, :cond_3

    const/4 p0, 0x0

    aget p1, p1, p0

    aget p0, p2, p0

    move p2, p1

    move p1, v5

    move v3, p1

    goto :goto_0

    :cond_3
    aget p0, p1, v3

    aget p1, p1, v2

    aget v3, p2, v3

    aget p2, p2, v2

    move v6, p1

    move p1, p0

    move p0, p2

    move p2, v6

    :goto_0
    cmpg-float v2, p1, p2

    if-nez v2, :cond_4

    move v0, v5

    goto :goto_1

    :cond_4
    sub-float/2addr v0, p1

    sub-float/2addr p2, p1

    div-float/2addr v0, p2

    :goto_1
    const/high16 p1, 0x3f800000    # 1.0f

    invoke-static {p1, v0}, Ljava/lang/Math;->min(FF)F

    move-result p1

    invoke-static {v5, p1}, Ljava/lang/Math;->max(FF)F

    move-result p1

    sub-float/2addr p0, v3

    mul-float/2addr p0, p1

    add-float/2addr p0, v3

    mul-float/2addr p0, v1

    return p0
.end method


# virtual methods
.method public OooO00o(Llyiahf/vczjk/bh3;Llyiahf/vczjk/ib3;I)Landroid/graphics/Typeface;
    .locals 0

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string p1, "sans-serif"

    invoke-static {p1, p2, p3}, Llyiahf/vczjk/pp3;->OooO0o(Ljava/lang/String;Llyiahf/vczjk/ib3;I)Landroid/graphics/Typeface;

    move-result-object p1

    return-object p1
.end method

.method public OooO0O0(JJ)J
    .locals 6

    const/16 v0, 0x20

    shr-long v1, p1, v0

    long-to-int v1, v1

    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v1

    shr-long v2, p3, v0

    long-to-int v2, v2

    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v2

    cmpg-float v1, v1, v2

    const-wide v2, 0xffffffffL

    if-gtz v1, :cond_0

    and-long v4, p1, v2

    long-to-int v1, v4

    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v1

    and-long v4, p3, v2

    long-to-int v4, v4

    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v4

    cmpg-float v1, v1, v4

    if-gtz v1, :cond_0

    const/high16 p1, 0x3f800000    # 1.0f

    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result p2

    int-to-long p2, p2

    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result p1

    int-to-long v4, p1

    shl-long p1, p2, v0

    and-long p3, v4, v2

    or-long/2addr p1, p3

    sget p3, Llyiahf/vczjk/t78;->OooO00o:I

    return-wide p1

    :cond_0
    invoke-static {p1, p2, p3, p4}, Llyiahf/vczjk/jp8;->OooO0oo(JJ)F

    move-result p1

    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result p2

    int-to-long p2, p2

    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result p1

    int-to-long v4, p1

    shl-long p1, p2, v0

    and-long p3, v4, v2

    or-long/2addr p1, p3

    sget p3, Llyiahf/vczjk/t78;->OooO00o:I

    return-wide p1
.end method

.method public OooO0OO(Ljava/io/Closeable;Ljava/lang/Throwable;Ljava/lang/Throwable;)V
    .locals 3

    sget-object p2, Llyiahf/vczjk/l01;->OooO00o:Ljava/util/logging/Logger;

    sget-object v0, Ljava/util/logging/Level;->WARNING:Ljava/util/logging/Level;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Suppressing exception thrown when closing "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p2, v0, p1, p3}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/Throwable;)V

    return-void
.end method

.method public OooO0Oo(Ljava/lang/Object;)Ljava/lang/String;
    .locals 2

    check-cast p1, Ljava/lang/Throwable;

    sget-object v0, Llyiahf/vczjk/l09;->OooO00o:Ljava/lang/String;

    move-object v0, p1

    :goto_0
    if-eqz v0, :cond_1

    instance-of v1, v0, Ljava/net/UnknownHostException;

    if-eqz v1, :cond_0

    const-string p1, ""

    return-object p1

    :cond_0
    invoke-virtual {v0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    move-result-object v0

    goto :goto_0

    :cond_1
    new-instance v0, Ljava/io/StringWriter;

    invoke-direct {v0}, Ljava/io/StringWriter;-><init>()V

    new-instance v1, Ljava/io/PrintWriter;

    invoke-direct {v1, v0}, Ljava/io/PrintWriter;-><init>(Ljava/io/Writer;)V

    invoke-virtual {p1, v1}, Ljava/lang/Throwable;->printStackTrace(Ljava/io/PrintWriter;)V

    invoke-virtual {v1}, Ljava/io/PrintWriter;->flush()V

    invoke-virtual {v0}, Ljava/io/StringWriter;->toString()Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method

.method public OooO0oO(Ljava/lang/Object;)Ljava/lang/Iterable;
    .locals 2

    check-cast p1, Llyiahf/vczjk/by0;

    sget v0, Llyiahf/vczjk/fs4;->OooOOOo:I

    invoke-interface {p1}, Llyiahf/vczjk/gz0;->OooOo0o()Llyiahf/vczjk/n3a;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/n3a;->OooO0O0()Ljava/util/Collection;

    move-result-object p1

    const-string v0, "getSupertypes(...)"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Ljava/lang/Iterable;

    invoke-static {p1}, Llyiahf/vczjk/d21;->Oooooo(Ljava/lang/Iterable;)Llyiahf/vczjk/vy;

    move-result-object p1

    sget-object v0, Llyiahf/vczjk/g13;->OooOoo0:Llyiahf/vczjk/g13;

    invoke-static {p1, v0}, Llyiahf/vczjk/ag8;->Oooo(Llyiahf/vczjk/wf8;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/e13;

    move-result-object p1

    new-instance v0, Llyiahf/vczjk/uy;

    const/4 v1, 0x2

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/uy;-><init>(Ljava/lang/Object;I)V

    return-object v0
.end method

.method public OooO0oo(Landroid/view/View;Ljava/lang/String;)V
    .locals 3

    invoke-static {p2}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    move-result-object v0

    invoke-virtual {v0}, Landroid/net/Uri;->getScheme()Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-virtual {v0}, Landroid/net/Uri;->buildUpon()Landroid/net/Uri$Builder;

    move-result-object v0

    const-string v1, "https"

    invoke-virtual {v0, v1}, Landroid/net/Uri$Builder;->scheme(Ljava/lang/String;)Landroid/net/Uri$Builder;

    move-result-object v0

    invoke-virtual {v0}, Landroid/net/Uri$Builder;->build()Landroid/net/Uri;

    move-result-object v0

    :cond_0
    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object p1

    new-instance v1, Landroid/content/Intent;

    const-string v2, "android.intent.action.VIEW"

    invoke-direct {v1, v2, v0}, Landroid/content/Intent;-><init>(Ljava/lang/String;Landroid/net/Uri;)V

    invoke-virtual {p1}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    move-result-object v0

    const-string v2, "com.android.browser.application_id"

    invoke-virtual {v1, v2, v0}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    :try_start_0
    invoke-virtual {p1, v1}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V
    :try_end_0
    .catch Landroid/content/ActivityNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    new-instance p1, Ljava/lang/StringBuilder;

    const-string v0, "Actvity was not found for the link: \'"

    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p2, "\'"

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    const-string p2, "LinkResolverDef"

    invoke-static {p2, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    return-void
.end method

.method public OooOO0O(Landroid/app/Application;)Ljava/util/Comparator;
    .locals 1

    new-instance p1, Llyiahf/vczjk/h93;

    const/16 v0, 0xf

    invoke-direct {p1, v0}, Llyiahf/vczjk/h93;-><init>(I)V

    return-object p1
.end method

.method public OooOO0o(Ljava/lang/Object;Ljava/lang/Object;)Z
    .locals 0

    if-ne p1, p2, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public OooOOO0(Llyiahf/vczjk/ib3;I)Landroid/graphics/Typeface;
    .locals 1

    const/4 v0, 0x0

    invoke-static {v0, p1, p2}, Llyiahf/vczjk/pp3;->OooO0o(Ljava/lang/String;Llyiahf/vczjk/ib3;I)Landroid/graphics/Typeface;

    move-result-object p1

    return-object p1
.end method

.method public OooOOoo(Landroid/app/Application;Llyiahf/vczjk/wu;)Ljava/lang/String;
    .locals 0

    const/4 p1, 0x0

    return-object p1
.end method

.method public OooooOo(JLlyiahf/vczjk/yn4;Llyiahf/vczjk/f62;)Llyiahf/vczjk/qqa;
    .locals 2

    new-instance p3, Llyiahf/vczjk/pf6;

    const-wide/16 v0, 0x0

    invoke-static {v0, v1, p1, p2}, Llyiahf/vczjk/ll6;->OooO0O0(JJ)Llyiahf/vczjk/wj7;

    move-result-object p1

    invoke-direct {p3, p1}, Llyiahf/vczjk/pf6;-><init>(Llyiahf/vczjk/wj7;)V

    return-object p3
.end method

.method public Oooooo0(Landroid/content/Context;)Ljava/util/Comparator;
    .locals 1

    const-string v0, "context"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p1, Llyiahf/vczjk/h93;

    const/16 v0, 0xe

    invoke-direct {p1, v0}, Llyiahf/vczjk/h93;-><init>(I)V

    return-object p1
.end method

.method public o00Oo0(Landroid/content/Context;Llyiahf/vczjk/xw;)Ljava/lang/String;
    .locals 1

    const-string v0, "context"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p1, "model"

    invoke-static {p2, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 p1, 0x0

    return-object p1
.end method

.method public toString()Ljava/lang/String;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/pp3;->OooOOO0:I

    sparse-switch v0, :sswitch_data_0

    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0

    :sswitch_0
    const-string v0, "RectangleShape"

    return-object v0

    :sswitch_1
    const-string v0, "Start"

    return-object v0

    :sswitch_2
    const-string v0, "ReferentialEqualityPolicy"

    return-object v0

    nop

    :sswitch_data_0
    .sparse-switch
        0x7 -> :sswitch_2
        0x8 -> :sswitch_1
        0x16 -> :sswitch_0
    .end sparse-switch
.end method
