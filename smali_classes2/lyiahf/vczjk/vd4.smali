.class public final Llyiahf/vczjk/vd4;
.super Llyiahf/vczjk/ng0;
.source "SourceFile"


# instance fields
.field public final OooOO0o:Ljava/lang/reflect/Constructor;


# direct methods
.method public constructor <init>(Ljava/lang/reflect/Constructor;)V
    .locals 1

    const-string v0, "constructor"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/vd4;->OooOO0o:Ljava/lang/reflect/Constructor;

    return-void
.end method


# virtual methods
.method public final OooOO0()Ljava/lang/String;
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/vd4;->OooOO0o:Ljava/lang/reflect/Constructor;

    invoke-virtual {v0}, Ljava/lang/reflect/Constructor;->getParameterTypes()[Ljava/lang/Class;

    move-result-object v1

    const-string v0, "getParameterTypes(...)"

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v5, Llyiahf/vczjk/g13;->OooOo0:Llyiahf/vczjk/g13;

    const-string v3, "<init>("

    const-string v4, ")V"

    const-string v2, ""

    const/16 v6, 0x18

    invoke-static/range {v1 .. v6}, Llyiahf/vczjk/sy;->o00000Oo([Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;I)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
