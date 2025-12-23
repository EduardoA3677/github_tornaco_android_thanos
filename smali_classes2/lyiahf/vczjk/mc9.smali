.class public final synthetic Llyiahf/vczjk/mc9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Z

.field public final synthetic OooOOO0:Llyiahf/vczjk/kl5;

.field public final synthetic OooOOOO:Ljava/lang/String;

.field public final synthetic OooOOOo:Ljava/lang/String;

.field public final synthetic OooOOo:I

.field public final synthetic OooOOo0:Llyiahf/vczjk/oe3;

.field public final synthetic OooOOoo:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/kl5;ZLjava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;II)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/mc9;->OooOOO0:Llyiahf/vczjk/kl5;

    iput-boolean p2, p0, Llyiahf/vczjk/mc9;->OooOOO:Z

    iput-object p3, p0, Llyiahf/vczjk/mc9;->OooOOOO:Ljava/lang/String;

    iput-object p4, p0, Llyiahf/vczjk/mc9;->OooOOOo:Ljava/lang/String;

    iput-object p5, p0, Llyiahf/vczjk/mc9;->OooOOo0:Llyiahf/vczjk/oe3;

    iput p6, p0, Llyiahf/vczjk/mc9;->OooOOo:I

    iput p7, p0, Llyiahf/vczjk/mc9;->OooOOoo:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/mc9;->OooOOo:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v6

    iget-object v4, p0, Llyiahf/vczjk/mc9;->OooOOo0:Llyiahf/vczjk/oe3;

    iget v7, p0, Llyiahf/vczjk/mc9;->OooOOoo:I

    iget-object v0, p0, Llyiahf/vczjk/mc9;->OooOOO0:Llyiahf/vczjk/kl5;

    iget-boolean v1, p0, Llyiahf/vczjk/mc9;->OooOOO:Z

    iget-object v2, p0, Llyiahf/vczjk/mc9;->OooOOOO:Ljava/lang/String;

    iget-object v3, p0, Llyiahf/vczjk/mc9;->OooOOOo:Ljava/lang/String;

    invoke-static/range {v0 .. v7}, Llyiahf/vczjk/er8;->OooOO0(Llyiahf/vczjk/kl5;ZLjava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
