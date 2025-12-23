.class public final Llyiahf/vczjk/hy2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/dx2;


# instance fields
.field public final OooO00o:Ljava/io/File;


# direct methods
.method public constructor <init>(Ljava/io/File;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/hy2;->OooO00o:Ljava/io/File;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 5

    new-instance p1, Llyiahf/vczjk/by8;

    sget-object v0, Llyiahf/vczjk/zp6;->OooOOO:Ljava/lang/String;

    iget-object v0, p0, Llyiahf/vczjk/hy2;->OooO00o:Ljava/io/File;

    invoke-static {v0}, Llyiahf/vczjk/xj0;->OooOOo0(Ljava/io/File;)Llyiahf/vczjk/zp6;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/ez2;->OooO00o:Llyiahf/vczjk/we4;

    new-instance v3, Llyiahf/vczjk/ky2;

    const/4 v4, 0x0

    invoke-direct {v3, v1, v2, v4, v4}, Llyiahf/vczjk/ky2;-><init>(Llyiahf/vczjk/zp6;Llyiahf/vczjk/ez2;Ljava/lang/String;Llyiahf/vczjk/bi7;)V

    invoke-static {}, Landroid/webkit/MimeTypeMap;->getSingleton()Landroid/webkit/MimeTypeMap;

    move-result-object v1

    invoke-static {v0}, Llyiahf/vczjk/d03;->OoooooO(Ljava/io/File;)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v1, v0}, Landroid/webkit/MimeTypeMap;->getMimeTypeFromExtension(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/zx1;->OooOOOO:Llyiahf/vczjk/zx1;

    invoke-direct {p1, v3, v0, v1}, Llyiahf/vczjk/by8;-><init>(Llyiahf/vczjk/nv3;Ljava/lang/String;Llyiahf/vczjk/zx1;)V

    return-object p1
.end method
