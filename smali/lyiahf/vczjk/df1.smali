.class public final Llyiahf/vczjk/df1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ia6;


# instance fields
.field public final synthetic OooOOO:Landroidx/compose/ui/tooling/ComposeViewAdapter;

.field public final OooOOO0:Llyiahf/vczjk/ha6;


# direct methods
.method public constructor <init>(Landroidx/compose/ui/tooling/ComposeViewAdapter;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/df1;->OooOOO:Landroidx/compose/ui/tooling/ComposeViewAdapter;

    new-instance p1, Llyiahf/vczjk/ha6;

    const/4 v0, 0x0

    invoke-direct {p1, v0}, Llyiahf/vczjk/ha6;-><init>(Ljava/lang/Runnable;)V

    iput-object p1, p0, Llyiahf/vczjk/df1;->OooOOO0:Llyiahf/vczjk/ha6;

    return-void
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/ha6;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/df1;->OooOOO0:Llyiahf/vczjk/ha6;

    return-object v0
.end method

.method public final getLifecycle()Llyiahf/vczjk/ky4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/df1;->OooOOO:Landroidx/compose/ui/tooling/ComposeViewAdapter;

    iget-object v0, v0, Landroidx/compose/ui/tooling/ComposeViewAdapter;->OooOooo:Llyiahf/vczjk/ef1;

    iget-object v0, v0, Llyiahf/vczjk/ef1;->OooOOO0:Llyiahf/vczjk/wy4;

    return-object v0
.end method
