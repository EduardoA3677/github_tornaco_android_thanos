.class public final Llyiahf/vczjk/pg4;
.super Llyiahf/vczjk/zh4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field public final OooOOo:Llyiahf/vczjk/qg4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/qg4;)V
    .locals 1

    const-string v0, "property"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Llyiahf/vczjk/zh4;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/pg4;->OooOOo:Llyiahf/vczjk/qg4;

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/pg4;->OooOOo:Llyiahf/vczjk/qg4;

    iget-object v0, v0, Llyiahf/vczjk/qg4;->OooOo0o:Ljava/lang/Object;

    invoke-interface {v0}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/pg4;

    filled-new-array {p1, p2, p3}, [Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ff4;->OooO0oo([Ljava/lang/Object;)Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.method public final OooO0oO()Llyiahf/vczjk/th4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/pg4;->OooOOo:Llyiahf/vczjk/qg4;

    return-object v0
.end method

.method public final OooOo00()Llyiahf/vczjk/ai4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/pg4;->OooOOo:Llyiahf/vczjk/qg4;

    return-object v0
.end method
