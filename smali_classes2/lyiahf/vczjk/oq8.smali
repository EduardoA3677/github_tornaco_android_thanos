.class public final Llyiahf/vczjk/oq8;
.super Llyiahf/vczjk/jp8;
.source "SourceFile"


# instance fields
.field public final OooOo:Llyiahf/vczjk/i88;

.field public final OooOo0O:Llyiahf/vczjk/jp8;

.field public final OooOo0o:J

.field public final OooOoO0:Llyiahf/vczjk/oOO0O00O;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jp8;JLlyiahf/vczjk/i88;Llyiahf/vczjk/oOO0O00O;)V
    .locals 1

    sget-object v0, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/oq8;->OooOo0O:Llyiahf/vczjk/jp8;

    iput-wide p2, p0, Llyiahf/vczjk/oq8;->OooOo0o:J

    iput-object p4, p0, Llyiahf/vczjk/oq8;->OooOo:Llyiahf/vczjk/i88;

    iput-object p5, p0, Llyiahf/vczjk/oq8;->OooOoO0:Llyiahf/vczjk/oOO0O00O;

    return-void
.end method


# virtual methods
.method public final OoooOOO(Llyiahf/vczjk/tp8;)V
    .locals 5

    new-instance v0, Llyiahf/vczjk/nq8;

    sget-object v1, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    iget-object v2, p0, Llyiahf/vczjk/oq8;->OooOoO0:Llyiahf/vczjk/oOO0O00O;

    iget-wide v3, p0, Llyiahf/vczjk/oq8;->OooOo0o:J

    invoke-direct {v0, p1, v2, v3, v4}, Llyiahf/vczjk/nq8;-><init>(Llyiahf/vczjk/tp8;Llyiahf/vczjk/oOO0O00O;J)V

    invoke-interface {p1, v0}, Llyiahf/vczjk/tp8;->OooO0O0(Llyiahf/vczjk/nc2;)V

    iget-object p1, v0, Llyiahf/vczjk/nq8;->task:Ljava/util/concurrent/atomic/AtomicReference;

    iget-object v2, p0, Llyiahf/vczjk/oq8;->OooOo:Llyiahf/vczjk/i88;

    invoke-virtual {v2, v0, v3, v4, v1}, Llyiahf/vczjk/i88;->OooO0OO(Ljava/lang/Runnable;JLjava/util/concurrent/TimeUnit;)Llyiahf/vczjk/nc2;

    move-result-object v1

    invoke-static {p1, v1}, Llyiahf/vczjk/tc2;->OooO0OO(Ljava/util/concurrent/atomic/AtomicReference;Llyiahf/vczjk/nc2;)Z

    iget-object p1, p0, Llyiahf/vczjk/oq8;->OooOo0O:Llyiahf/vczjk/jp8;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/jp8;->OooO0Oo(Llyiahf/vczjk/tp8;)V

    return-void
.end method
