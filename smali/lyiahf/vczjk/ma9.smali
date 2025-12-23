.class public abstract Llyiahf/vczjk/ma9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/l48;


# instance fields
.field public final OooOOO:Ljava/lang/String;

.field public final OooOOO0:Llyiahf/vczjk/ca9;

.field public OooOOOO:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ca9;Ljava/lang/String;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ma9;->OooOOO0:Llyiahf/vczjk/ca9;

    iput-object p2, p0, Llyiahf/vczjk/ma9;->OooOOO:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public final OooO0Oo()V
    .locals 2

    iget-boolean v0, p0, Llyiahf/vczjk/ma9;->OooOOOO:Z

    if-nez v0, :cond_0

    return-void

    :cond_0
    const/16 v0, 0x15

    const-string v1, "statement is closed"

    invoke-static {v0, v1}, Llyiahf/vczjk/vl6;->OooOooo(ILjava/lang/String;)V

    const/4 v0, 0x0

    throw v0
.end method
