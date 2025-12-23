.class public final Llyiahf/vczjk/et4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Landroidx/compose/foundation/lazy/layout/OooO0OO;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroidx/compose/foundation/lazy/layout/OooO0OO;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Landroidx/compose/foundation/lazy/layout/OooO0OO;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/et4;->this$0:Landroidx/compose/foundation/lazy/layout/OooO0OO;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/et4;->this$0:Landroidx/compose/foundation/lazy/layout/OooO0OO;

    iget-object v0, v0, Landroidx/compose/foundation/lazy/layout/OooO0OO;->OooOO0:Llyiahf/vczjk/dt4;

    if-eqz v0, :cond_0

    invoke-static {v0}, Llyiahf/vczjk/ye5;->OooOoO0(Llyiahf/vczjk/fg2;)V

    :cond_0
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
