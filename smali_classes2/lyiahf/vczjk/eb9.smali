.class public abstract Llyiahf/vczjk/eb9;
.super Llyiahf/vczjk/zo1;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/lf3;


# instance fields
.field private final arity:I


# direct methods
.method public constructor <init>(ILlyiahf/vczjk/yo1;)V
    .locals 0

    invoke-direct {p0, p2}, Llyiahf/vczjk/zo1;-><init>(Llyiahf/vczjk/yo1;)V

    iput p1, p0, Llyiahf/vczjk/eb9;->arity:I

    return-void
.end method


# virtual methods
.method public getArity()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/eb9;->arity:I

    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/p70;->getCompletion()Llyiahf/vczjk/yo1;

    move-result-object v0

    if-nez v0, :cond_0

    sget-object v0, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-virtual {v0, p0}, Llyiahf/vczjk/zm7;->OooO0oo(Llyiahf/vczjk/lf3;)Ljava/lang/String;

    move-result-object v0

    const-string v1, "renderLambdaToString(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0

    :cond_0
    invoke-super {p0}, Llyiahf/vczjk/p70;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
