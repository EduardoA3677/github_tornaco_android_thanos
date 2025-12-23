.class public final Llyiahf/vczjk/qg4;
.super Llyiahf/vczjk/sh4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/rg4;


# instance fields
.field public final OooOo0o:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yf4;Llyiahf/vczjk/ua7;)V
    .locals 1

    const-string v0, "container"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "descriptor"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/sh4;-><init>(Llyiahf/vczjk/yf4;Llyiahf/vczjk/ua7;)V

    sget-object p1, Llyiahf/vczjk/ww4;->OooOOO0:Llyiahf/vczjk/ww4;

    new-instance p2, Llyiahf/vczjk/o0oOOo;

    const/16 v0, 0x18

    invoke-direct {p2, p0, v0}, Llyiahf/vczjk/o0oOOo;-><init>(Ljava/lang/Object;I)V

    invoke-static {p1, p2}, Llyiahf/vczjk/jp8;->Oooo00o(Llyiahf/vczjk/ww4;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kp4;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/qg4;->OooOo0o:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final OooO0OO()Llyiahf/vczjk/gg4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/qg4;->OooOo0o:Ljava/lang/Object;

    invoke-interface {v0}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/pg4;

    return-object v0
.end method
