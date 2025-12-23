.class public final Llyiahf/vczjk/sd8;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $dragConsumed:Llyiahf/vczjk/dl7;

.field final synthetic $observer:Llyiahf/vczjk/dp5;

.field final synthetic $selectionAdjustment:Llyiahf/vczjk/md8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/dp5;Llyiahf/vczjk/md8;Llyiahf/vczjk/dl7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/sd8;->$observer:Llyiahf/vczjk/dp5;

    iput-object p2, p0, Llyiahf/vczjk/sd8;->$selectionAdjustment:Llyiahf/vczjk/md8;

    iput-object p3, p0, Llyiahf/vczjk/sd8;->$dragConsumed:Llyiahf/vczjk/dl7;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Llyiahf/vczjk/ky6;

    iget-object v0, p0, Llyiahf/vczjk/sd8;->$observer:Llyiahf/vczjk/dp5;

    iget-wide v1, p1, Llyiahf/vczjk/ky6;->OooO0OO:J

    iget-object v3, p0, Llyiahf/vczjk/sd8;->$selectionAdjustment:Llyiahf/vczjk/md8;

    invoke-interface {v0, v1, v2, v3}, Llyiahf/vczjk/dp5;->OooO0OO(JLlyiahf/vczjk/md8;)Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/ky6;->OooO00o()V

    iget-object p1, p0, Llyiahf/vczjk/sd8;->$dragConsumed:Llyiahf/vczjk/dl7;

    const/4 v0, 0x1

    iput-boolean v0, p1, Llyiahf/vczjk/dl7;->element:Z

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
