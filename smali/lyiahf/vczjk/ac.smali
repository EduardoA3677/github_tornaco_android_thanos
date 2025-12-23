.class public final Llyiahf/vczjk/ac;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $callbacks:Llyiahf/vczjk/bc;

.field final synthetic $context:Landroid/content/Context;


# direct methods
.method public constructor <init>(Landroid/content/Context;Llyiahf/vczjk/bc;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ac;->$context:Landroid/content/Context;

    iput-object p2, p0, Llyiahf/vczjk/ac;->$callbacks:Llyiahf/vczjk/bc;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/qc2;

    iget-object p1, p0, Llyiahf/vczjk/ac;->$context:Landroid/content/Context;

    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/ac;->$callbacks:Llyiahf/vczjk/bc;

    invoke-virtual {p1, v0}, Landroid/content/Context;->registerComponentCallbacks(Landroid/content/ComponentCallbacks;)V

    iget-object p1, p0, Llyiahf/vczjk/ac;->$context:Landroid/content/Context;

    iget-object v0, p0, Llyiahf/vczjk/ac;->$callbacks:Llyiahf/vczjk/bc;

    new-instance v1, Llyiahf/vczjk/xb;

    const/4 v2, 0x1

    invoke-direct {v1, v2, p1, v0}, Llyiahf/vczjk/xb;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    return-object v1
.end method
