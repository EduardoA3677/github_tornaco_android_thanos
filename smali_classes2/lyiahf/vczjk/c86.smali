.class public final Llyiahf/vczjk/c86;
.super Llyiahf/vczjk/oo0o0O0;
.source "SourceFile"


# instance fields
.field public final OooOOO:Llyiahf/vczjk/i88;

.field public final OooOOOO:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/o76;Llyiahf/vczjk/i88;I)V
    .locals 0

    invoke-direct {p0, p1}, Llyiahf/vczjk/oo0o0O0;-><init>(Llyiahf/vczjk/o76;)V

    iput-object p2, p0, Llyiahf/vczjk/c86;->OooOOO:Llyiahf/vczjk/i88;

    iput p3, p0, Llyiahf/vczjk/c86;->OooOOOO:I

    return-void
.end method


# virtual methods
.method public final OooO0o0(Llyiahf/vczjk/j86;)V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/c86;->OooOOO:Llyiahf/vczjk/i88;

    instance-of v1, v0, Llyiahf/vczjk/vx9;

    iget-object v2, p0, Llyiahf/vczjk/oo0o0O0;->OooOOO0:Llyiahf/vczjk/o76;

    if-eqz v1, :cond_0

    invoke-virtual {v2, p1}, Llyiahf/vczjk/o76;->OooO0Oo(Llyiahf/vczjk/j86;)V

    return-void

    :cond_0
    invoke-virtual {v0}, Llyiahf/vczjk/i88;->OooO00o()Llyiahf/vczjk/h88;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/b86;

    iget v3, p0, Llyiahf/vczjk/c86;->OooOOOO:I

    invoke-direct {v1, p1, v0, v3}, Llyiahf/vczjk/b86;-><init>(Llyiahf/vczjk/j86;Llyiahf/vczjk/h88;I)V

    invoke-virtual {v2, v1}, Llyiahf/vczjk/o76;->OooO0Oo(Llyiahf/vczjk/j86;)V

    return-void
.end method
