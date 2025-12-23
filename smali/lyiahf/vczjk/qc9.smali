.class public final synthetic Llyiahf/vczjk/qc9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Z

.field public final synthetic OooOOO0:Llyiahf/vczjk/kl5;

.field public final synthetic OooOOOO:Z

.field public final synthetic OooOOOo:Llyiahf/vczjk/nc9;

.field public final synthetic OooOOo:Llyiahf/vczjk/qj8;

.field public final synthetic OooOOo0:Llyiahf/vczjk/rr5;

.field public final synthetic OooOOoo:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/kl5;ZZLlyiahf/vczjk/nc9;Llyiahf/vczjk/rr5;Llyiahf/vczjk/qj8;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/qc9;->OooOOO0:Llyiahf/vczjk/kl5;

    iput-boolean p2, p0, Llyiahf/vczjk/qc9;->OooOOO:Z

    iput-boolean p3, p0, Llyiahf/vczjk/qc9;->OooOOOO:Z

    iput-object p4, p0, Llyiahf/vczjk/qc9;->OooOOOo:Llyiahf/vczjk/nc9;

    iput-object p5, p0, Llyiahf/vczjk/qc9;->OooOOo0:Llyiahf/vczjk/rr5;

    iput-object p6, p0, Llyiahf/vczjk/qc9;->OooOOo:Llyiahf/vczjk/qj8;

    iput p7, p0, Llyiahf/vczjk/qc9;->OooOOoo:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    move-object v6, p1

    check-cast v6, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/qc9;->OooOOoo:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v7

    iget-object v4, p0, Llyiahf/vczjk/qc9;->OooOOo0:Llyiahf/vczjk/rr5;

    iget-object v5, p0, Llyiahf/vczjk/qc9;->OooOOo:Llyiahf/vczjk/qj8;

    iget-object v0, p0, Llyiahf/vczjk/qc9;->OooOOO0:Llyiahf/vczjk/kl5;

    iget-boolean v1, p0, Llyiahf/vczjk/qc9;->OooOOO:Z

    iget-boolean v2, p0, Llyiahf/vczjk/qc9;->OooOOOO:Z

    iget-object v3, p0, Llyiahf/vczjk/qc9;->OooOOOo:Llyiahf/vczjk/nc9;

    invoke-static/range {v0 .. v7}, Landroidx/compose/material3/OooO0O0;->OooO0O0(Llyiahf/vczjk/kl5;ZZLlyiahf/vczjk/nc9;Llyiahf/vczjk/rr5;Llyiahf/vczjk/qj8;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
