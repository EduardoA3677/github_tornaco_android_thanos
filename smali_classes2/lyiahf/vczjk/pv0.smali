.class public final Llyiahf/vczjk/pv0;
.super Llyiahf/vczjk/f84;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ov0;


# instance fields
.field public final OooOOo0:Llyiahf/vczjk/k84;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/k84;)V
    .locals 0

    invoke-direct {p0}, Llyiahf/vczjk/r45;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/pv0;->OooOOo0:Llyiahf/vczjk/k84;

    return-void
.end method


# virtual methods
.method public final OooO0O0(Ljava/lang/Throwable;)Z
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/f84;->OooOO0()Llyiahf/vczjk/k84;

    move-result-object v0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/k84;->OooOo0O(Ljava/lang/Throwable;)Z

    move-result p1

    return p1
.end method

.method public final OooOO0O()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method

.method public final OooOO0o(Ljava/lang/Throwable;)V
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/f84;->OooOO0()Llyiahf/vczjk/k84;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/pv0;->OooOOo0:Llyiahf/vczjk/k84;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/k84;->OooOOo(Ljava/lang/Object;)Z

    return-void
.end method
