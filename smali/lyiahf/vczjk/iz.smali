.class public final Llyiahf/vczjk/iz;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/cx2;


# instance fields
.field public final synthetic OooO00o:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/iz;->OooO00o:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o(Ljava/lang/Object;Llyiahf/vczjk/hf6;)Llyiahf/vczjk/dx2;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/iz;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Landroid/net/Uri;

    invoke-virtual {p1}, Landroid/net/Uri;->getScheme()Ljava/lang/String;

    move-result-object v0

    const-string v1, "android.resource"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_0

    const/4 p1, 0x0

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/jz;

    const/4 v1, 0x2

    invoke-direct {v0, p1, p2, v1}, Llyiahf/vczjk/jz;-><init>(Landroid/net/Uri;Llyiahf/vczjk/hf6;I)V

    move-object p1, v0

    :goto_0
    return-object p1

    :pswitch_0
    check-cast p1, Ljava/io/File;

    new-instance p2, Llyiahf/vczjk/hy2;

    invoke-direct {p2, p1}, Llyiahf/vczjk/hy2;-><init>(Ljava/io/File;)V

    return-object p2

    :pswitch_1
    check-cast p1, Landroid/graphics/drawable/Drawable;

    new-instance v0, Llyiahf/vczjk/bd0;

    const/4 v1, 0x2

    invoke-direct {v0, p1, p2, v1}, Llyiahf/vczjk/bd0;-><init>(Ljava/lang/Object;Llyiahf/vczjk/hf6;I)V

    return-object v0

    :pswitch_2
    check-cast p1, Landroid/net/Uri;

    invoke-virtual {p1}, Landroid/net/Uri;->getScheme()Ljava/lang/String;

    move-result-object v0

    const-string v1, "content"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_1

    const/4 p1, 0x0

    goto :goto_1

    :cond_1
    new-instance v0, Llyiahf/vczjk/jz;

    const/4 v1, 0x1

    invoke-direct {v0, p1, p2, v1}, Llyiahf/vczjk/jz;-><init>(Landroid/net/Uri;Llyiahf/vczjk/hf6;I)V

    move-object p1, v0

    :goto_1
    return-object p1

    :pswitch_3
    check-cast p1, Ljava/nio/ByteBuffer;

    new-instance v0, Llyiahf/vczjk/bd0;

    const/4 v1, 0x1

    invoke-direct {v0, p1, p2, v1}, Llyiahf/vczjk/bd0;-><init>(Ljava/lang/Object;Llyiahf/vczjk/hf6;I)V

    return-object v0

    :pswitch_4
    check-cast p1, Landroid/graphics/Bitmap;

    new-instance v0, Llyiahf/vczjk/bd0;

    const/4 v1, 0x0

    invoke-direct {v0, p1, p2, v1}, Llyiahf/vczjk/bd0;-><init>(Ljava/lang/Object;Llyiahf/vczjk/hf6;I)V

    return-object v0

    :pswitch_5
    check-cast p1, Landroid/net/Uri;

    invoke-static {p1}, Llyiahf/vczjk/OooOOO0;->OooO0OO(Landroid/net/Uri;)Z

    move-result v0

    if-nez v0, :cond_2

    const/4 p1, 0x0

    goto :goto_2

    :cond_2
    new-instance v0, Llyiahf/vczjk/jz;

    const/4 v1, 0x0

    invoke-direct {v0, p1, p2, v1}, Llyiahf/vczjk/jz;-><init>(Landroid/net/Uri;Llyiahf/vczjk/hf6;I)V

    move-object p1, v0

    :goto_2
    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
