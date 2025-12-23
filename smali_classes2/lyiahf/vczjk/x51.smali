.class public final Llyiahf/vczjk/x51;
.super Llyiahf/vczjk/t51;
.source "SourceFile"


# instance fields
.field public final OooOOO:J

.field public final OooOOO0:Llyiahf/vczjk/t51;

.field public final OooOOOO:Llyiahf/vczjk/i88;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/t51;JLlyiahf/vczjk/i88;)V
    .locals 1

    sget-object v0, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/x51;->OooOOO0:Llyiahf/vczjk/t51;

    iput-wide p2, p0, Llyiahf/vczjk/x51;->OooOOO:J

    iput-object p4, p0, Llyiahf/vczjk/x51;->OooOOOO:Llyiahf/vczjk/i88;

    return-void
.end method


# virtual methods
.method public final Ooooo0o(Llyiahf/vczjk/d61;)V
    .locals 4

    new-instance v0, Llyiahf/vczjk/w51;

    sget-object v1, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    iget-wide v1, p0, Llyiahf/vczjk/x51;->OooOOO:J

    iget-object v3, p0, Llyiahf/vczjk/x51;->OooOOOO:Llyiahf/vczjk/i88;

    invoke-direct {v0, p1, v1, v2, v3}, Llyiahf/vczjk/w51;-><init>(Llyiahf/vczjk/d61;JLlyiahf/vczjk/i88;)V

    iget-object p1, p0, Llyiahf/vczjk/x51;->OooOOO0:Llyiahf/vczjk/t51;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/t51;->Ooooo00(Llyiahf/vczjk/d61;)V

    return-void
.end method
