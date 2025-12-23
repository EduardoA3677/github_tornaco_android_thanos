.class public final Llyiahf/vczjk/q76;
.super Llyiahf/vczjk/oo0o0O0;
.source "SourceFile"


# instance fields
.field public final OooOOO:J

.field public final OooOOOO:Llyiahf/vczjk/i88;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/o76;JLlyiahf/vczjk/i88;)V
    .locals 1

    sget-object v0, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    invoke-direct {p0, p1}, Llyiahf/vczjk/oo0o0O0;-><init>(Llyiahf/vczjk/o76;)V

    iput-wide p2, p0, Llyiahf/vczjk/q76;->OooOOO:J

    iput-object p4, p0, Llyiahf/vczjk/q76;->OooOOOO:Llyiahf/vczjk/i88;

    return-void
.end method


# virtual methods
.method public final OooO0o0(Llyiahf/vczjk/j86;)V
    .locals 4

    new-instance v0, Llyiahf/vczjk/mg8;

    invoke-direct {v0, p1}, Llyiahf/vczjk/mg8;-><init>(Llyiahf/vczjk/j86;)V

    iget-object p1, p0, Llyiahf/vczjk/q76;->OooOOOO:Llyiahf/vczjk/i88;

    invoke-virtual {p1}, Llyiahf/vczjk/i88;->OooO00o()Llyiahf/vczjk/h88;

    move-result-object p1

    new-instance v1, Llyiahf/vczjk/p76;

    sget-object v2, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    iget-wide v2, p0, Llyiahf/vczjk/q76;->OooOOO:J

    invoke-direct {v1, v0, v2, v3, p1}, Llyiahf/vczjk/p76;-><init>(Llyiahf/vczjk/j86;JLlyiahf/vczjk/h88;)V

    iget-object p1, p0, Llyiahf/vczjk/oo0o0O0;->OooOOO0:Llyiahf/vczjk/o76;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/o76;->OooO0Oo(Llyiahf/vczjk/j86;)V

    return-void
.end method
