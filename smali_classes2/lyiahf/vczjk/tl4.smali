.class public final Llyiahf/vczjk/tl4;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final synthetic OooO00o:Llyiahf/vczjk/ul4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ul4;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/tl4;->OooO00o:Llyiahf/vczjk/ul4;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/tl4;->OooO00o:Llyiahf/vczjk/ul4;

    iget-object v1, v0, Llyiahf/vczjk/ul4;->OooO0O0:Lgithub/tornaco/android/thanos/core/Logger;

    invoke-static {}, Llyiahf/vczjk/m6a;->o0000O00()Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/xl4;->OooO00o(Ljava/lang/String;)V

    iget-object v0, v0, Llyiahf/vczjk/ul4;->OooO0OO:Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/lm4;

    sget-object v2, Llyiahf/vczjk/xu0;->OooOOo0:Llyiahf/vczjk/xu0;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/lm4;

    invoke-direct {v1, v2}, Llyiahf/vczjk/lm4;-><init>(Llyiahf/vczjk/xu0;)V

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v2, 0x0

    invoke-virtual {v0, v2, v1}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    return-void
.end method

.method public final OooO0O0(I)V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/tl4;->OooO00o:Llyiahf/vczjk/ul4;

    iget-object v1, v0, Llyiahf/vczjk/ul4;->OooO0O0:Lgithub/tornaco/android/thanos/core/Logger;

    iget-object v0, v0, Llyiahf/vczjk/ul4;->OooO0OO:Llyiahf/vczjk/s29;

    const/16 v1, 0x123

    const/4 v2, 0x0

    if-eq p1, v1, :cond_1

    const/16 v1, 0x231

    if-eq p1, v1, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/lm4;

    sget-object v1, Llyiahf/vczjk/xu0;->OooOOO:Llyiahf/vczjk/xu0;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p1, Llyiahf/vczjk/lm4;

    invoke-direct {p1, v1}, Llyiahf/vczjk/lm4;-><init>(Llyiahf/vczjk/xu0;)V

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v0, v2, p1}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    goto :goto_0

    :cond_0
    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/lm4;

    sget-object v1, Llyiahf/vczjk/xu0;->OooOOOO:Llyiahf/vczjk/xu0;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p1, Llyiahf/vczjk/lm4;

    invoke-direct {p1, v1}, Llyiahf/vczjk/lm4;-><init>(Llyiahf/vczjk/xu0;)V

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v0, v2, p1}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    goto :goto_0

    :cond_1
    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/lm4;

    sget-object v1, Llyiahf/vczjk/xu0;->OooOOOo:Llyiahf/vczjk/xu0;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p1, Llyiahf/vczjk/lm4;

    invoke-direct {p1, v1}, Llyiahf/vczjk/lm4;-><init>(Llyiahf/vczjk/xu0;)V

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v0, v2, p1}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    :goto_0
    invoke-static {v2}, Llyiahf/vczjk/xl4;->OooO00o(Ljava/lang/String;)V

    return-void
.end method
