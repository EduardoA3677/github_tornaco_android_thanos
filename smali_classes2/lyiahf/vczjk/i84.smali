.class public final Llyiahf/vczjk/i84;
.super Llyiahf/vczjk/f84;
.source "SourceFile"


# instance fields
.field public final OooOOo:Llyiahf/vczjk/j84;

.field public final OooOOo0:Llyiahf/vczjk/k84;

.field public final OooOOoo:Llyiahf/vczjk/pv0;

.field public final OooOo00:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/k84;Llyiahf/vczjk/j84;Llyiahf/vczjk/pv0;Ljava/lang/Object;)V
    .locals 0

    invoke-direct {p0}, Llyiahf/vczjk/r45;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/i84;->OooOOo0:Llyiahf/vczjk/k84;

    iput-object p2, p0, Llyiahf/vczjk/i84;->OooOOo:Llyiahf/vczjk/j84;

    iput-object p3, p0, Llyiahf/vczjk/i84;->OooOOoo:Llyiahf/vczjk/pv0;

    iput-object p4, p0, Llyiahf/vczjk/i84;->OooOo00:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final OooOO0O()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final OooOO0o(Ljava/lang/Throwable;)V
    .locals 6

    iget-object p1, p0, Llyiahf/vczjk/i84;->OooOOoo:Llyiahf/vczjk/pv0;

    iget-object v0, p0, Llyiahf/vczjk/i84;->OooOOo0:Llyiahf/vczjk/k84;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p1}, Llyiahf/vczjk/k84;->OoooO0O(Llyiahf/vczjk/r45;)Llyiahf/vczjk/pv0;

    move-result-object v1

    iget-object v2, p0, Llyiahf/vczjk/i84;->OooOOo:Llyiahf/vczjk/j84;

    iget-object v3, p0, Llyiahf/vczjk/i84;->OooOo00:Ljava/lang/Object;

    if-eqz v1, :cond_0

    invoke-virtual {v0, v2, v1, v3}, Llyiahf/vczjk/k84;->OooooO0(Llyiahf/vczjk/j84;Llyiahf/vczjk/pv0;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    goto :goto_0

    :cond_0
    iget-object v1, v2, Llyiahf/vczjk/j84;->OooOOO0:Llyiahf/vczjk/a26;

    new-instance v4, Llyiahf/vczjk/z05;

    const/4 v5, 0x2

    invoke-direct {v4, v5}, Llyiahf/vczjk/z05;-><init>(I)V

    invoke-virtual {v1, v4, v5}, Llyiahf/vczjk/r45;->OooO0OO(Llyiahf/vczjk/r45;I)Z

    invoke-static {p1}, Llyiahf/vczjk/k84;->OoooO0O(Llyiahf/vczjk/r45;)Llyiahf/vczjk/pv0;

    move-result-object p1

    if-eqz p1, :cond_1

    invoke-virtual {v0, v2, p1, v3}, Llyiahf/vczjk/k84;->OooooO0(Llyiahf/vczjk/j84;Llyiahf/vczjk/pv0;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_1

    :goto_0
    return-void

    :cond_1
    invoke-virtual {v0, v2, v3}, Llyiahf/vczjk/k84;->OooOoo0(Llyiahf/vczjk/j84;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/k84;->OooOO0(Ljava/lang/Object;)V

    return-void
.end method
