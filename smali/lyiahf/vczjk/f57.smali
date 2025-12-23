.class public final Llyiahf/vczjk/f57;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/uy4;


# static fields
.field public static final OooOo0:Llyiahf/vczjk/f57;


# instance fields
.field public OooOOO:I

.field public OooOOO0:I

.field public OooOOOO:Z

.field public OooOOOo:Z

.field public final OooOOo:Llyiahf/vczjk/wy4;

.field public OooOOo0:Landroid/os/Handler;

.field public final OooOOoo:Llyiahf/vczjk/xy3;

.field public final OooOo00:Llyiahf/vczjk/oO0OOo0o;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/f57;

    invoke-direct {v0}, Llyiahf/vczjk/f57;-><init>()V

    sput-object v0, Llyiahf/vczjk/f57;->OooOo0:Llyiahf/vczjk/f57;

    return-void
.end method

.method public constructor <init>()V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/f57;->OooOOOO:Z

    iput-boolean v0, p0, Llyiahf/vczjk/f57;->OooOOOo:Z

    new-instance v0, Llyiahf/vczjk/wy4;

    invoke-direct {v0, p0}, Llyiahf/vczjk/wy4;-><init>(Llyiahf/vczjk/uy4;)V

    iput-object v0, p0, Llyiahf/vczjk/f57;->OooOOo:Llyiahf/vczjk/wy4;

    new-instance v0, Llyiahf/vczjk/xy3;

    const/16 v1, 0xa

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/xy3;-><init>(Ljava/lang/Object;I)V

    iput-object v0, p0, Llyiahf/vczjk/f57;->OooOOoo:Llyiahf/vczjk/xy3;

    new-instance v0, Llyiahf/vczjk/oO0OOo0o;

    const/16 v1, 0x1c

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/oO0OOo0o;-><init>(Ljava/lang/Object;I)V

    iput-object v0, p0, Llyiahf/vczjk/f57;->OooOo00:Llyiahf/vczjk/oO0OOo0o;

    return-void
.end method


# virtual methods
.method public final OooO0O0()V
    .locals 2

    iget v0, p0, Llyiahf/vczjk/f57;->OooOOO:I

    const/4 v1, 0x1

    add-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/f57;->OooOOO:I

    if-ne v0, v1, :cond_1

    iget-boolean v0, p0, Llyiahf/vczjk/f57;->OooOOOO:Z

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/f57;->OooOOo:Llyiahf/vczjk/wy4;

    sget-object v1, Llyiahf/vczjk/iy4;->ON_RESUME:Llyiahf/vczjk/iy4;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/wy4;->OooO0o(Llyiahf/vczjk/iy4;)V

    const/4 v0, 0x0

    iput-boolean v0, p0, Llyiahf/vczjk/f57;->OooOOOO:Z

    return-void

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/f57;->OooOOo0:Landroid/os/Handler;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-object v1, p0, Llyiahf/vczjk/f57;->OooOOoo:Llyiahf/vczjk/xy3;

    invoke-virtual {v0, v1}, Landroid/os/Handler;->removeCallbacks(Ljava/lang/Runnable;)V

    :cond_1
    return-void
.end method

.method public final getLifecycle()Llyiahf/vczjk/ky4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f57;->OooOOo:Llyiahf/vczjk/wy4;

    return-object v0
.end method
