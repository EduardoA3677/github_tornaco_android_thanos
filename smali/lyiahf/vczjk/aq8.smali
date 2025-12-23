.class public final Llyiahf/vczjk/aq8;
.super Ljava/util/concurrent/CancellationException;
.source "SourceFile"


# instance fields
.field private final runner:Llyiahf/vczjk/gq8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/gq8;)V
    .locals 1

    const-string v0, "runner"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "Cancelled isolated runner"

    invoke-direct {p0, v0}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    iput-object p1, p0, Llyiahf/vczjk/aq8;->runner:Llyiahf/vczjk/gq8;

    return-void
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/gq8;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/aq8;->runner:Llyiahf/vczjk/gq8;

    return-object v0
.end method
