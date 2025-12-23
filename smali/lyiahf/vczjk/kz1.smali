.class public final Llyiahf/vczjk/kz1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $applicationContext:Landroid/content/Context;

.field final synthetic this$0:Llyiahf/vczjk/lz1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/lz1;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Landroid/content/Context;Llyiahf/vczjk/lz1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/kz1;->$applicationContext:Landroid/content/Context;

    iput-object p2, p0, Llyiahf/vczjk/kz1;->this$0:Llyiahf/vczjk/lz1;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 4

    sget-object v0, Llyiahf/vczjk/zp6;->OooOOO:Ljava/lang/String;

    iget-object v0, p0, Llyiahf/vczjk/kz1;->$applicationContext:Landroid/content/Context;

    const-string v1, "applicationContext"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/kz1;->this$0:Llyiahf/vczjk/lz1;

    iget-object v1, v1, Llyiahf/vczjk/lz1;->OooO00o:Ljava/lang/String;

    new-instance v2, Ljava/io/File;

    invoke-virtual {v0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v0

    invoke-virtual {v0}, Landroid/content/Context;->getFilesDir()Ljava/io/File;

    move-result-object v0

    const-string v3, "datastore/"

    invoke-virtual {v3, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-direct {v2, v0, v1}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    invoke-virtual {v2}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object v0

    const-string v1, "applicationContext.dataS\u2026le(fileName).absolutePath"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v1, 0x0

    invoke-static {v0, v1}, Llyiahf/vczjk/xj0;->OooOOOo(Ljava/lang/String;Z)Llyiahf/vczjk/zp6;

    move-result-object v0

    return-object v0
.end method
