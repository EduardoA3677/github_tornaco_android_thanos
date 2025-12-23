.class public final Llyiahf/vczjk/qx9;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Landroid/content/Context;

.field public final OooO0O0:Llyiahf/vczjk/ak1;

.field public final OooO0OO:Llyiahf/vczjk/pa0;

.field public final OooO0Oo:Llyiahf/vczjk/ak1;

.field public final OooO0o0:Llyiahf/vczjk/ak1;


# direct methods
.method public constructor <init>(Landroid/content/Context;Llyiahf/vczjk/rqa;)V
    .locals 6

    new-instance v0, Llyiahf/vczjk/pa0;

    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v1

    const-string v2, "context.applicationContext"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v3, 0x0

    invoke-direct {v0, v1, p2, v3}, Llyiahf/vczjk/pa0;-><init>(Landroid/content/Context;Llyiahf/vczjk/rqa;I)V

    new-instance v1, Llyiahf/vczjk/pa0;

    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v3

    invoke-static {v3, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v4, 0x1

    invoke-direct {v1, v3, p2, v4}, Llyiahf/vczjk/pa0;-><init>(Landroid/content/Context;Llyiahf/vczjk/rqa;I)V

    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v3

    invoke-static {v3, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v4, Llyiahf/vczjk/l06;->OooO00o:Ljava/lang/String;

    new-instance v4, Llyiahf/vczjk/k06;

    invoke-direct {v4, v3, p2}, Llyiahf/vczjk/k06;-><init>(Landroid/content/Context;Llyiahf/vczjk/rqa;)V

    new-instance v3, Llyiahf/vczjk/pa0;

    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v5

    invoke-static {v5, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v2, 0x2

    invoke-direct {v3, v5, p2, v2}, Llyiahf/vczjk/pa0;-><init>(Landroid/content/Context;Llyiahf/vczjk/rqa;I)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/qx9;->OooO00o:Landroid/content/Context;

    iput-object v0, p0, Llyiahf/vczjk/qx9;->OooO0O0:Llyiahf/vczjk/ak1;

    iput-object v1, p0, Llyiahf/vczjk/qx9;->OooO0OO:Llyiahf/vczjk/pa0;

    iput-object v4, p0, Llyiahf/vczjk/qx9;->OooO0Oo:Llyiahf/vczjk/ak1;

    iput-object v3, p0, Llyiahf/vczjk/qx9;->OooO0o0:Llyiahf/vczjk/ak1;

    return-void
.end method
