.class public final Llyiahf/vczjk/p27;
.super Llyiahf/vczjk/cl7;
.source "SourceFile"


# instance fields
.field public final OooO0o:Landroidx/recyclerview/widget/RecyclerView;

.field public final OooO0oO:Llyiahf/vczjk/bl7;

.field public final OooO0oo:Llyiahf/vczjk/qf0;


# direct methods
.method public constructor <init>(Landroidx/recyclerview/widget/RecyclerView;)V
    .locals 2

    invoke-direct {p0, p1}, Llyiahf/vczjk/cl7;-><init>(Landroidx/recyclerview/widget/RecyclerView;)V

    iget-object v0, p0, Llyiahf/vczjk/cl7;->OooO0o0:Llyiahf/vczjk/bl7;

    iput-object v0, p0, Llyiahf/vczjk/p27;->OooO0oO:Llyiahf/vczjk/bl7;

    new-instance v0, Llyiahf/vczjk/qf0;

    const/4 v1, 0x5

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/qf0;-><init>(Ljava/lang/Object;I)V

    iput-object v0, p0, Llyiahf/vczjk/p27;->OooO0oo:Llyiahf/vczjk/qf0;

    iput-object p1, p0, Llyiahf/vczjk/p27;->OooO0o:Landroidx/recyclerview/widget/RecyclerView;

    return-void
.end method


# virtual methods
.method public final OooOO0()Llyiahf/vczjk/o0oO0Ooo;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/p27;->OooO0oo:Llyiahf/vczjk/qf0;

    return-object v0
.end method
