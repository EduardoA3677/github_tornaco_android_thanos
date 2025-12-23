.class public final Llyiahf/vczjk/df;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $layoutDirection:Llyiahf/vczjk/yn4;

.field final synthetic $onDismissRequest:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field

.field final synthetic $popupLayout:Llyiahf/vczjk/zz6;

.field final synthetic $properties:Llyiahf/vczjk/d07;

.field final synthetic $testTag:Ljava/lang/String;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/zz6;Llyiahf/vczjk/le3;Llyiahf/vczjk/d07;Ljava/lang/String;Llyiahf/vczjk/yn4;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/df;->$popupLayout:Llyiahf/vczjk/zz6;

    iput-object p2, p0, Llyiahf/vczjk/df;->$onDismissRequest:Llyiahf/vczjk/le3;

    iput-object p3, p0, Llyiahf/vczjk/df;->$properties:Llyiahf/vczjk/d07;

    iput-object p4, p0, Llyiahf/vczjk/df;->$testTag:Ljava/lang/String;

    iput-object p5, p0, Llyiahf/vczjk/df;->$layoutDirection:Llyiahf/vczjk/yn4;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/df;->$popupLayout:Llyiahf/vczjk/zz6;

    iget-object v1, p0, Llyiahf/vczjk/df;->$onDismissRequest:Llyiahf/vczjk/le3;

    iget-object v2, p0, Llyiahf/vczjk/df;->$properties:Llyiahf/vczjk/d07;

    iget-object v3, p0, Llyiahf/vczjk/df;->$testTag:Ljava/lang/String;

    iget-object v4, p0, Llyiahf/vczjk/df;->$layoutDirection:Llyiahf/vczjk/yn4;

    invoke-virtual {v0, v1, v2, v3, v4}, Llyiahf/vczjk/zz6;->OooOO0O(Llyiahf/vczjk/le3;Llyiahf/vczjk/d07;Ljava/lang/String;Llyiahf/vczjk/yn4;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
